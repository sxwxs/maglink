import pytest

flask = pytest.importorskip("flask")
from flask import Flask

from maglink import AuthCore, MemoryStore, ConsoleMailer
from maglink.flask import EmailAuth


@pytest.fixture
def app_and_mailer():
    mailer = ConsoleMailer()
    core = AuthCore(
        store=MemoryStore(),
        mailer=mailer,
        verify_url_base="http://localhost/api/auth/verify",
        allowed_emails=["alice@example.test"],
        admin_emails=["alice@example.test"],
    )
    auth = EmailAuth(core, require_captcha=False)
    app = Flask(__name__)
    app.secret_key = "test-secret"

    @app.get("/protected")
    @auth.login_required
    def protected():
        return {"ok": True, "secret": 42}

    app.register_blueprint(auth.blueprint())
    return app, mailer


def _token(mailer):
    return [l for l in mailer.last["body"].splitlines() if "token=" in l][0].split("token=")[1].strip()


def test_full_flask_flow(app_and_mailer):
    app, mailer = app_and_mailer
    device = app.test_client()       # the waiting browser
    inbox = app.test_client()        # a different client opening the email link

    # protected route blocked
    assert device.get("/protected").status_code == 401

    # start login (binds request_id to device's session cookie)
    r = device.post("/api/auth/request", json={"email": "alice@example.test"})
    assert r.status_code == 200 and r.get_json()["ok"]
    user_code = r.get_json()["user_code"]
    assert user_code

    token = _token(mailer)

    # confirm page (GET) is side-effect-free
    page = inbox.get(f"/api/auth/verify?token={token}")
    assert page.status_code == 200
    assert user_code not in page.get_data(as_text=True)
    # still pending
    assert device.get("/api/auth/status").get_json()["status"] == "pending"

    # token alone cannot approve; deliberate confirm requires the device code.
    c = inbox.post("/api/auth/verify/confirm", json={"token": token})
    assert c.status_code == 400
    assert device.get("/api/auth/status").get_json()["status"] == "pending"

    # deliberate confirm (POST) from the inbox client with the waiting-device code
    c = inbox.post("/api/auth/verify/confirm", json={"token": token, "user_code": user_code})
    assert c.get_json()["ok"]

    # device poll now approved -> session established
    s = device.get("/api/auth/status").get_json()
    assert s["status"] == "approved" and s["email"] == "alice@example.test"

    # protected route now works for the device, admin flag set
    assert device.get("/protected").get_json()["secret"] == 42
    assert device.get("/api/auth/state").get_json()["is_admin"] is True

    # logout
    device.post("/api/auth/logout")
    assert device.get("/protected").status_code == 401


def test_confirm_from_wrong_session_does_not_log_in_attacker(app_and_mailer):
    app, mailer = app_and_mailer
    device = app.test_client()
    attacker = app.test_client()

    r = device.post("/api/auth/request", json={"email": "alice@example.test"})
    user_code = r.get_json()["user_code"]
    token = _token(mailer)
    # attacker confirms the link with the code, but they never had the request_id in session
    attacker.post("/api/auth/verify/confirm", json={"token": token, "user_code": user_code})
    # attacker's own status has no pending request -> not logged in
    assert attacker.get("/api/auth/status").get_json()["status"] == "expired"
    assert attacker.get("/protected").status_code == 401
    # the legitimate device, which holds the request_id, completes the login
    assert device.get("/api/auth/status").get_json()["status"] == "approved"


def test_disallowed_email_status_is_uniform(app_and_mailer):
    app, mailer = app_and_mailer
    device = app.test_client()

    r = device.post("/api/auth/request", json={"email": "mallory@example.test"})
    assert r.status_code == 200 and r.get_json()["ok"]
    assert mailer.last is None
    assert device.get("/api/auth/status").get_json()["status"] == "pending"


def test_x_forwarded_for_is_not_trusted_by_default():
    mailer = ConsoleMailer()
    core = AuthCore(
        store=MemoryStore(),
        mailer=mailer,
        verify_url_base="http://localhost/api/auth/verify",
        allowed_emails=["alice@example.test", "bob@example.test"],
        rate_max=1,
    )
    auth = EmailAuth(core, require_captcha=False)
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.register_blueprint(auth.blueprint())
    client = app.test_client()

    first = client.post(
        "/api/auth/request",
        json={"email": "alice@example.test"},
        headers={"X-Forwarded-For": "203.0.113.1"},
    )
    assert first.status_code == 200

    second = client.post(
        "/api/auth/request",
        json={"email": "bob@example.test"},
        headers={"X-Forwarded-For": "203.0.113.2"},
    )
    assert second.status_code == 429
