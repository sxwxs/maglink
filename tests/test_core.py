import time

import pytest

from maglink import AuthCore, MemoryStore, SqliteStore, ConsoleMailer, AuthError, RateLimited


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
    # confirm context is side-effect-free and shows the same user_code
    ctx = core.confirm_context(token)
    assert ctx["valid"] and ctx["user_code"] == lr.user_code

    # still pending until the deliberate confirm
    assert core.poll_status(lr.request_id)["status"] == "pending"

    core.confirm(token)
    res = core.poll_status(lr.request_id)
    assert res["status"] == "approved"
    assert res["email"] == "alice@example.test"
    assert res["is_admin"] is True


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
    core.confirm(_token_from_email(mailer))
    assert core.poll_status(lr.request_id)["status"] == "approved"
    # consumed: second poll no longer returns approved
    assert core.poll_status(lr.request_id)["status"] in ("expired", "pending")


def test_disallowed_email_is_uniform_but_never_approvable():
    core, mailer = make_core()
    lr = core.start_login("mallory@example.test", require_captcha=False)
    # uniform: still returns a request_id + user_code, no error
    assert lr.request_id and lr.user_code
    # but no email sent and nothing approvable
    assert mailer.last is None
    assert core.poll_status(lr.request_id)["status"] == "expired"


def test_expired_token():
    core, mailer = make_core(code_ttl=0.05)
    lr = core.start_login("alice@example.test", require_captcha=False)
    token = _token_from_email(mailer)
    time.sleep(0.1)
    assert core.confirm_context(token)["valid"] is False
    with pytest.raises(AuthError):
        core.confirm(token)


def test_rate_limit():
    core, _ = make_core(rate_max=2)
    for _ in range(2):
        core.start_login("alice@example.test", require_captcha=False, client_ip="1.2.3.4")
    with pytest.raises(RateLimited):
        core.start_login("alice@example.test", require_captcha=False, client_ip="1.2.3.4")


def test_captcha_required():
    core, _ = make_core()
    with pytest.raises(AuthError):
        core.start_login(
            "alice@example.test",
            captcha_given="WRONG",
            captcha_expected="RIGHT",
            require_captcha=True,
        )


def test_sqlite_store_roundtrip(tmp_path):
    store = SqliteStore(str(tmp_path / "auth.db"))
    core, mailer = make_core(store=store)
    lr = core.start_login("alice@example.test", require_captcha=False)
    core.confirm(_token_from_email(mailer))
    assert core.poll_status(lr.request_id)["status"] == "approved"
