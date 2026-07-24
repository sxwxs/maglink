---
name: maglink-email-login
description: Implements secure email login with the Python maglink library, including Flask integration, dynamic identities, device-code confirmation, and delivery through a MailDispatch API key. Use when adding passwordless email authentication, magic-link login, admin roles, or MailDispatch-backed authentication email to a Python application.
license: MIT
compatibility: Python 3.9 or newer. Flask integration requires maglink[flask]. MailDispatch integration requires an API key with mail:send and mail:authentication scopes.
metadata:
  author: sxwxs
  package: maglink
---

# Implement email login with maglink and MailDispatch

Use this skill when a Python application needs passwordless email login. Read
the repository [`README.md`](../../../README.md) and the runnable
[`examples/maildispatch_login.py`](../../../examples/maildispatch_login.py)
before changing an unfamiliar application.

## Security model

maglink is not a one-click magic link. Preserve all three parts of the flow:

1. The waiting browser owns a private `request_id` in its signed session.
2. The email owns a private `verify_token` in the link.
3. The waiting browser displays a short `user_code` that must be entered on the
   email confirmation page.

The confirmation `GET` must remain side-effect-free. Approval happens only on
`POST /verify/confirm` with both the email token and the device code. The
waiting browser must poll `/status` and consume the approval once.

Never simplify this into “click link and immediately log in.” Never include the
`user_code` in the email.

## Required information

Before implementation, identify:

- the web framework and application factory;
- the public HTTPS application URL;
- how Flask sessions are configured;
- the application's user table and role model;
- whether users are allowlisted or loaded dynamically;
- the shared token store to use in production;
- the MailDispatch base URL, sender ID, and API-key environment variable;
- whether MailDispatch recipient policy permits application users;
- whether CAPTCHA is required;
- trusted reverse-proxy behavior.

Ask the user for missing deployment-specific values. Do not hard-code secrets.

## Dependencies

For Flask:

```bash
pip install "maglink[flask]"
```

Recommended development dependency declaration:

```toml
[project]
dependencies = [
  "maglink[flask]>=0.3.0",
]
```

## MailDispatch API key

Create a dedicated MailDispatch API key with exactly the needed scopes:

```text
mail:send
mail:authentication
```

Restrict it to the authentication sender when sender restrictions are used.
Store it in an environment variable such as:

```bash
export MAILDISPATCH_API_KEY="md_live_..."
```

Do not put the key in source code, YAML committed to Git, browser JavaScript,
logs, or error responses.

The endpoint passed to `HttpMailer` is the complete submit endpoint:

```text
https://mail.example.com/api/v1/messages
```

## Standard Flask implementation

Use this as the default integration shape:

```python
import os

from flask import Flask, jsonify
from maglink import AuthCore, HttpMailer, SqliteStore
from maglink.flask import EmailAuth


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ["SECRET_KEY"]
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=True,
    )

    mailer = HttpMailer(
        endpoint=os.environ["MAILDISPATCH_API_URL"],
        api_key=os.environ["MAILDISPATCH_API_KEY"],
        sender_id=os.getenv("MAILDISPATCH_SENDER_ID", "system"),
        timeout=10,
    )
    core = AuthCore(
        store=SqliteStore(os.getenv("MAGLINK_DB", "data/maglink.db")),
        mailer=mailer,
        verify_url_base=f"{os.environ['PUBLIC_BASE_URL'].rstrip('/')}/api/auth/verify",
        identity_provider=ApplicationIdentityProvider(),
        login_sender_id=os.getenv("MAILDISPATCH_SENDER_ID", "system"),
        code_ttl=900,
        rate_max=5,
        rate_window=900,
        confirm_max_attempts=8,
    )
    auth = EmailAuth(
        core,
        require_captcha=True,
        trust_proxy_headers=False,
    )
    app.register_blueprint(auth.blueprint(url_prefix="/api/auth"))
    app.extensions["email_auth"] = auth

    @app.get("/api/me")
    @auth.login_required
    def me():
        return jsonify({"ok": True, "user": auth.current_user()})

    return app
```

Adapt names to the host project instead of creating a second Flask app.

## Verified registration before approval

For public registration where mailbox ownership must be proven before a
pending user is created, use `EmailVerificationCore` with `EmailVerifier`.
Do not temporarily make pending users login-eligible.

```python
from maglink import EmailVerificationCore
from maglink.flask import EmailVerifier

verification_core = EmailVerificationCore(
    store=store,
    mailer=mailer,
    verify_url_base=f"{PUBLIC_BASE_URL}/api/register/verify",
    email_allowed=lambda email: public_registration_enabled or is_invited(email),
)
verifier = EmailVerifier(verification_core, require_captcha=True)
app.register_blueprint(verifier.blueprint(url_prefix="/api/register"))
```

After `/api/register/status` returns `verified`, the host must consume the
verified address once from the same waiting-browser session:

```python
email = verifier.verified_email()
if email is None:
    abort(403)
if not public_registration_enabled and not is_invited(email):
    abort(403)
create_pending_user(email)
verifier.consume_verified_email()  # only after successful persistence
```

Use `verified_email()` for non-consuming validation and consume it only after
successful user persistence, so correctable validation errors do not force a
new verification email. `email_allowed` is re-evaluated before maglink returns
`verified`, but the host must also re-check eligibility at the final
registration mutation because
policy can change after polling. Email verification must not establish a login
session. The application's identity provider should allow login only after both
email verification and administrator approval are true.

Login and email-verification cores can safely share one store: their default
rate-limit namespaces are `login` and `verification`. Give additional flows an
explicit unique `rate_namespace`; cores intentionally using the same namespace
must use compatible rate-limit settings.

## Identity provider

Prefer a dynamic provider for database-backed applications:

```python
from maglink import Identity


class ApplicationIdentityProvider:
    def get_identity(self, email: str):
        normalized = email.strip().lower()
        user = UserRepository.find_by_email(normalized)
        if user is None or not user.enabled or not user.can_login:
            return None
        return Identity(
            id=str(user.id),
            email=user.email,
            roles=(user.role,),
            claims={"display_name": user.display_name},
        )

    def can_login(self, email: str) -> bool:
        return self.get_identity(email) is not None
```

Requirements:

- normalize email consistently;
- return `None` for disabled or disallowed users;
- derive roles from server-side data;
- never trust roles sent by the browser;
- keep claims JSON-serializable;
- ensure the `admin` role is present only for administrators.

For a small fixed allowlist, pass `allowed_emails` and `admin_emails` to
`AuthCore` instead.

## Frontend flow

The waiting page should:

1. load `/api/auth/captcha` when CAPTCHA is enabled;
2. submit `{email, captcha}` to `/api/auth/request`;
3. display the returned `user_code` prominently;
4. poll `/api/auth/status` every 1–2 seconds;
5. redirect or refresh after `status === "approved"`;
6. stop polling and offer retry after `status === "expired"`.

Minimal request:

```javascript
const response = await fetch('/api/auth/request', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email, captcha})
});
const result = await response.json();
showCode(result.user_code);
```

Do not send the `request_id` to browser JavaScript; the Flask adapter binds it
to the signed session.

## MailDispatch recipient policy

Check MailDispatch before declaring the integration complete:

- `service_users`: every login recipient must be an enabled MailDispatch user;
- `allowlist`: every login recipient must be listed;
- `any`: MailDispatch accepts recipients, while the application identity
  provider remains responsible for deciding who may log in.

A mismatch causes the login-mail enqueue to fail. Do not solve this by setting
`allow_anyone=True` in maglink unless unrestricted login is explicitly desired.

## Store selection

- Tests/local single process: `MemoryStore`
- Small persistent deployment: `SqliteStore`
- Multiple machines or high availability: implement `TokenStore` using the
  application's shared database or Redis

A custom store must provide atomic `set_status()` compare-and-set behavior and
atomic `incr_rate()` behavior. Do not use process-local memory behind multiple
workers.

## Reverse proxy handling

Leave `trust_proxy_headers=False` by default. If the application is behind a
trusted proxy, configure the framework's proxy middleware correctly first.
Only then enable proxy-header handling. Never trust client-supplied
`X-Forwarded-For` on a directly reachable server.

## Required tests

Add tests for at least:

1. allowed user requests a login email;
2. disallowed email gets a uniform-looking pending response but no email;
3. confirmation `GET` does not approve login;
4. token without device code is rejected;
5. wrong device code is rejected;
6. correct token and code approve the waiting browser;
7. a different browser cannot inherit the waiting session;
8. approval is consumed once;
9. expired requests fail;
10. request and confirmation rate limits work;
11. disabled users lose access on the next request;
12. MailDispatch rejection leaves no pending auth request;
13. untrusted `X-Forwarded-For` does not bypass rate limits.

Use a fake or console mailer in unit tests. Do not call a live SMTP server or
live MailDispatch service from the normal test suite.

## Completion checklist

Before finishing:

- [ ] Secrets come only from environment or a secret manager.
- [ ] `verify_url_base` is the public HTTPS URL.
- [ ] MailDispatch key has `mail:send` and `mail:authentication`.
- [ ] MailDispatch sender restrictions include the configured sender.
- [ ] MailDispatch recipient policy matches the application's users.
- [ ] A server-side identity provider controls login and roles.
- [ ] Confirmation `GET` has no side effects.
- [ ] The email does not contain the device code.
- [ ] The waiting device polls status using its session.
- [ ] Secure session-cookie settings are enabled.
- [ ] Production uses a persistent/shared token store.
- [ ] Proxy headers are trusted only behind a trusted proxy.
- [ ] Login, denial, expiry, and mail failure are tested.

## Common mistakes

Do not:

- email both the token and device code;
- approve on `GET /verify`;
- expose the token to the waiting page;
- establish the session in the browser that opened the email;
- use `ConsoleMailer` in production;
- use `MemoryStore` across multiple workers;
- put MailDispatch API keys in frontend code;
- grant an authentication key unrelated admin scopes;
- accept authorization roles from request JSON;
- trust forwarding headers by default;
- reveal whether an email is on the login allowlist.
