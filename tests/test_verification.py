import pytest

flask = pytest.importorskip("flask")
from flask import Flask

from maglink import AuthCore, ConsoleMailer, EmailVerificationCore, MemoryStore
from maglink.flask import EmailVerifier


def _token(mailer):
    return [
        line for line in mailer.last["body"].splitlines() if "token=" in line
    ][0].split("token=")[1].strip()


def make_app():
    mailer = ConsoleMailer()
    core = EmailVerificationCore(
        store=MemoryStore(),
        mailer=mailer,
        verify_url_base="https://example.test/api/register/verify",
    )
    verifier = EmailVerifier(core, require_captcha=False)
    app = Flask(__name__)
    app.secret_key = "test-secret"
    app.register_blueprint(verifier.blueprint(url_prefix="/api/register"))

    @app.get("/peek")
    def peek():
        return {"email": verifier.verified_email()}

    @app.post("/complete")
    def complete():
        email = verifier.consume_verified_email()
        if email is None:
            return {"ok": False, "error": "verification_required"}, 403
        return {"ok": True, "email": email}

    return app, mailer


def test_email_verification_does_not_create_login_and_is_consumed_once():
    app, mailer = make_app()
    waiting = app.test_client()
    inbox = app.test_client()

    started = waiting.post("/api/register/request", json={"email": "new@example.test"})
    assert started.status_code == 200
    code = started.get_json()["user_code"]
    token = _token(mailer)
    assert code not in mailer.last["body"]

    page = inbox.get(f"/api/register/verify?token={token}")
    assert page.status_code == 200
    assert code not in page.get_data(as_text=True)
    assert waiting.get("/api/register/status").get_json()["status"] == "pending"

    bad = inbox.post(
        "/api/register/verify/confirm",
        json={"token": token, "user_code": "WRONG"},
    )
    assert bad.status_code == 400

    confirmed = inbox.post(
        "/api/register/verify/confirm",
        json={"token": token, "user_code": code},
    )
    assert confirmed.status_code == 200
    assert waiting.get("/api/register/status").get_json()["status"] == "verified"

    assert waiting.get("/peek").get_json()["email"] == "new@example.test"
    assert waiting.get("/peek").get_json()["email"] == "new@example.test"

    completed = waiting.post("/complete")
    assert completed.get_json()["email"] == "new@example.test"
    assert waiting.post("/complete").status_code == 403
    assert inbox.post("/complete").status_code == 403


def test_verification_rechecks_dynamic_eligibility_before_completion():
    allowed = {"value": True}
    mailer = ConsoleMailer()
    core = EmailVerificationCore(
        store=MemoryStore(),
        mailer=mailer,
        verify_url_base="https://example.test/api/register/verify",
        email_allowed=lambda email: allowed["value"],
    )
    request = core.start_login("new@example.test", require_captcha=False)
    core.confirm(_token(mailer), request.user_code)
    allowed["value"] = False
    assert core.poll_status(request.request_id)["status"] == "expired"


def test_login_and_verification_have_separate_rate_namespaces():
    store = MemoryStore()
    verification_mailer = ConsoleMailer()
    login_mailer = ConsoleMailer()
    verification = EmailVerificationCore(
        store=store,
        mailer=verification_mailer,
        verify_url_base="https://example.test/api/register/verify",
        rate_max=1,
    )
    login = AuthCore(
        store=store,
        mailer=login_mailer,
        verify_url_base="https://example.test/api/auth/verify",
        allowed_emails=["same@example.test"],
        rate_max=1,
    )
    verification.start_login(
        "same@example.test", require_captcha=False, client_ip="203.0.113.10"
    )
    result = login.start_login(
        "same@example.test", require_captcha=False, client_ip="203.0.113.10"
    )
    assert result.request_id


def test_verification_accepts_unregistered_email():
    app, mailer = make_app()
    client = app.test_client()
    response = client.post(
        "/api/register/request", json={"email": "any-valid@example.test"}
    )
    assert response.status_code == 200
    assert mailer.last is not None
    assert mailer.last["message"].metadata["flow"] == "email_verification"
