import time

import pytest

from maglink import (
    AuthCore,
    MemoryStore,
    SqliteStore,
    ConsoleMailer,
    AuthError,
    MailDeliveryError,
    RateLimited,
)


def make_core(store=None, **kw):
    mailer = ConsoleMailer()
    core = AuthCore(
        store=store or MemoryStore(),
        mailer=mailer,
        verify_url_base="https://example.test/api/auth/verify",
        allowed_emails=["alice@example.test"],
        admin_emails=["alice@example.test"],
        code_ttl=kw.pop("code_ttl", 600),
        rate_max=kw.pop("rate_max", 5),
        **kw,
    )
    return core, mailer


def _token_from_email(mailer):
    body = mailer.last["body"]
    line = [l for l in body.splitlines() if "token=" in l][0]
    return line.split("token=")[1].strip()


def test_happy_path_device_flow():
    core, mailer = make_core()
    lr = core.start_login("alice@example.test", require_captcha=False)
    assert lr.request_id and lr.user_code
    # waiting device polls -> pending
    assert core.poll_status(lr.request_id)["status"] == "pending"

    token = _token_from_email(mailer)
    # confirm context is side-effect-free and does not reveal the user_code
    ctx = core.confirm_context(token)
    assert ctx["valid"] and ctx["email"] == "alice@example.test"
    assert "user_code" not in ctx

    # still pending until the deliberate confirm
    assert core.poll_status(lr.request_id)["status"] == "pending"

    core.confirm(token, lr.user_code)
    res = core.poll_status(lr.request_id)
    assert res["status"] == "approved"
    assert res["email"] == "alice@example.test"
    assert res["is_admin"] is True


def test_confirm_requires_user_code():
    core, mailer = make_core()
    lr = core.start_login("alice@example.test", require_captcha=False)
    token = _token_from_email(mailer)

    with pytest.raises(AuthError):
        core.confirm(token)
    with pytest.raises(AuthError):
        core.confirm(token, "WRONG")

    # Dashes/spaces/case are presentation only.
    core.confirm(token, lr.user_code.replace("-", " ").lower())
    assert core.poll_status(lr.request_id)["status"] == "approved"


def test_email_does_not_include_user_code():
    core, mailer = make_core()
    lr = core.start_login("alice@example.test", require_captcha=False)
    assert lr.user_code not in mailer.last["body"]


def test_confirm_context_has_no_side_effects():
    # A prefetch (GET) of the link must NOT approve the login.
    core, mailer = make_core()
    lr = core.start_login("alice@example.test", require_captcha=False)
    token = _token_from_email(mailer)
    for _ in range(3):
        core.confirm_context(token)
    assert core.poll_status(lr.request_id)["status"] == "pending"


def test_status_is_single_use():
    core, mailer = make_core()
    lr = core.start_login("alice@example.test", require_captcha=False)
    core.confirm(_token_from_email(mailer), lr.user_code)
    assert core.poll_status(lr.request_id)["status"] == "approved"
    # consumed: second poll no longer returns approved
    assert core.poll_status(lr.request_id)["status"] in ("expired", "pending")


def test_disallowed_email_status_is_uniform_until_expiry():
    core, mailer = make_core(code_ttl=0.05)
    lr = core.start_login("mallory@example.test", require_captcha=False)
    # uniform: still returns a request_id + user_code and stays pending for a
    # while, matching the visible status shape for an allowed email.
    assert lr.request_id and lr.user_code
    assert mailer.last is None
    assert core.poll_status(lr.request_id)["status"] == "pending"
    time.sleep(0.1)
    assert core.poll_status(lr.request_id)["status"] == "expired"


def test_expired_token():
    core, mailer = make_core(code_ttl=0.05)
    lr = core.start_login("alice@example.test", require_captcha=False)
    token = _token_from_email(mailer)
    time.sleep(0.1)
    assert core.confirm_context(token)["valid"] is False
    with pytest.raises(AuthError):
        core.confirm(token, lr.user_code)


def test_rate_limit():
    core, _ = make_core(rate_max=2)
    for _ in range(2):
        core.start_login("alice@example.test", require_captcha=False, client_ip="1.2.3.4")
    with pytest.raises(RateLimited):
        core.start_login("alice@example.test", require_captcha=False, client_ip="1.2.3.4")


def test_confirmation_attempts_are_rate_limited():
    core, mailer = make_core(confirm_max_attempts=2)
    lr = core.start_login("alice@example.test", require_captcha=False)
    token = _token_from_email(mailer)
    for _ in range(2):
        with pytest.raises(AuthError):
            core.confirm(token, "WRONG")
    with pytest.raises(RateLimited):
        core.confirm(token, lr.user_code)
    assert core.poll_status(lr.request_id)["status"] == "pending"


def test_mail_rejection_deletes_pending_request():
    store = MemoryStore()

    class RejectingMailer:
        def send(self, message):
            raise MailDeliveryError("rejected")

    core = AuthCore(
        store=store,
        mailer=RejectingMailer(),
        verify_url_base="https://example.test/api/auth/verify",
        allowed_emails=["alice@example.test"],
    )
    with pytest.raises(AuthError, match="Could not queue"):
        core.start_login("alice@example.test", require_captcha=False)
    assert store._by_id == {}


def test_sqlite_store_roundtrip_and_rate_cleanup(tmp_path):
    store = SqliteStore(str(tmp_path / "auth.db"))
    core, mailer = make_core(store=store)
    lr = core.start_login("alice@example.test", require_captcha=False)
    core.confirm(_token_from_email(mailer), lr.user_code)
    assert core.poll_status(lr.request_id)["status"] == "approved"

    assert store.incr_rate("old", 100, 10) == 1
    assert store.incr_rate("new", 111, 10) == 1
    assert store._connection().execute(
        "SELECT COUNT(*) FROM maglink_rates WHERE key='old'"
    ).fetchone()[0] == 0


def test_captcha_required():
    core, _ = make_core()
    with pytest.raises(AuthError):
        core.start_login(
            "alice@example.test",
            captcha_given="WRONG",
            captcha_expected="RIGHT",
            require_captcha=True,
        )
