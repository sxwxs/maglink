# maglink

`maglink` is an email magic-link authentication library with device-flow
confirmation. It provides a framework-independent authentication core and an
optional Flask adapter.

Unlike a traditional magic link, opening the email does not immediately log in
a browser. The user must also enter the short code shown on the device that
started the login. This protects the flow from mail scanners, link prefetchers,
forwarded messages, and accidental link opening.

## Features

- Framework-independent `AuthCore`
- Optional Flask blueprint and authentication decorators
- Short device-code confirmation
- Dynamic identity and authorization providers
- In-memory and SQLite token stores
- Console, SMTP, and HTTP mail delivery adapters
- MailDispatch integration with priority and idempotency support
- CAPTCHA and request/confirmation rate limits
- Single-use authentication requests
- No required runtime dependencies for the core package

## Installation

Install the core library:

```bash
pip install maglink
```

Install the Flask adapter:

```bash
pip install "maglink[flask]"
```

## Authentication flow

1. The waiting device calls `start_login()` or `POST /api/auth/request`.
2. maglink creates:
   - a private `request_id`, stored in the waiting browser session;
   - a short `user_code`, displayed on the waiting device;
   - a private `verify_token`, sent only by email.
3. The email link opens a side-effect-free confirmation page.
4. The user enters the device code on that page.
5. The waiting device polls the status endpoint.
6. The approved request is consumed once and the user session is established.

The email token proves access to the mailbox. The device code proves that the
person confirming the email can also see the device that started the login.
Both are required.

## Quick start with Flask

```python
import os

from flask import Flask, jsonify
from maglink import AuthCore, SqliteStore, ConsoleMailer
from maglink.flask import EmailAuth

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,
)

core = AuthCore(
    store=SqliteStore("data/auth.db"),
    mailer=ConsoleMailer(),  # Development only
    verify_url_base="https://app.example.com/api/auth/verify",
    allowed_emails=["alice@example.com"],
    admin_emails=["alice@example.com"],
)
auth = EmailAuth(core, require_captcha=True)
app.register_blueprint(auth.blueprint(url_prefix="/api/auth"))


@app.get("/api/me")
@auth.login_required
def me():
    return jsonify(auth.current_user())


@app.get("/api/admin")
@auth.admin_required
def admin():
    return jsonify({"ok": True, "message": "admin access granted"})
```

`ConsoleMailer` prints the login email and must only be used for local
development. See `examples/flask_app.py` for a runnable waiting-page example.

## Send login email through MailDispatch

Create a MailDispatch API key with both scopes:

```text
mail:send
mail:authentication
```

Then configure `HttpMailer`:

```python
import os

from maglink import AuthCore, HttpMailer, SqliteStore

mailer = HttpMailer(
    endpoint="https://mail.example.com/api/v1/messages",
    api_key=os.environ["MAILDISPATCH_API_KEY"],
    sender_id="system",
    timeout=10,
)

core = AuthCore(
    store=SqliteStore("data/auth.db"),
    mailer=mailer,
    verify_url_base="https://app.example.com/api/auth/verify",
    allowed_emails=["alice@example.com"],
    admin_emails=["alice@example.com"],
    login_sender_id="system",
)
```

Authentication messages are submitted with:

- `purpose="authentication"`
- authentication priority
- a stable idempotency key for the login request
- the maglink request ID in message metadata

MailDispatch must permit the recipient. If its recipient policy is
`service_users`, every application user must also exist as an enabled
MailDispatch user. For independent application user databases, use a suitable
MailDispatch allowlist or `any` recipient policy and enforce login eligibility
inside the application's `IdentityProvider`.

A complete integration is available in `examples/maildispatch_login.py`.

## Verify an email before registration

Use `EmailVerificationCore` and the Flask `EmailVerifier` when a host needs to
prove mailbox ownership without creating a login session. This supports flows
such as verified registration followed by administrator approval.

```python
from maglink import EmailVerificationCore, SqliteStore
from maglink.flask import EmailVerifier

verification_core = EmailVerificationCore(
    store=SqliteStore("data/auth.db"),
    mailer=mailer,
    verify_url_base="https://app.example.com/api/register/verify",
    # Optional: when omitted, every syntactically valid email is eligible.
    email_allowed=lambda email: public_registration or is_invited(email),
)
verifier = EmailVerifier(verification_core, require_captcha=True)
app.register_blueprint(verifier.blueprint(url_prefix="/api/register"))

@app.post("/register/complete")
def complete_registration():
    email = verifier.verified_email()
    if email is None:
        return {"error": "email_verification_required"}, 403
    if not public_registration and not is_invited(email):
        return {"error": "registration_not_allowed"}, 403
    create_pending_user(email)
    verifier.consume_verified_email()  # only after successful persistence
    return {"ok": True, "status": "pending"}, 201
```

The verified email is bound to the waiting browser's signed session.
`verified_email()` reads it without consuming it, allowing correctable input
errors to be retried without another email. Call `consume_verified_email()`
only after successful persistence. `EmailVerifier` never creates an
authenticated user session. `email_allowed` is checked both before mail
delivery and again before
`verified` is returned. Because policy can still change between status polling
and the final database mutation, the application must re-check current
registration eligibility immediately before creating the user. The application
remains responsible for registration, approval, and roles.

## Dynamic identities

Authentication proves control of an email address. Authorization should come
from the host application's database.

Implement `IdentityProvider`:

```python
from maglink import Identity


class DatabaseIdentityProvider:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    def get_identity(self, email: str):
        with self.session_factory() as session:
            user = session.find_user_by_email(email.strip().lower())
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

Pass it to `AuthCore`:

```python
core = AuthCore(
    store=store,
    mailer=mailer,
    verify_url_base="https://app.example.com/api/auth/verify",
    identity_provider=DatabaseIdentityProvider(Session),
)
```

`EmailAuth.current_user()` refreshes the identity from the provider on every
request. Disabling or demoting a user therefore takes effect without waiting
for the browser session to expire.

For small static deployments, use `allowed_emails`, `admin_emails`, and
`allow_anyone`. An email in `admin_emails` is automatically allowed to log in.

## Core API

### `AuthCore`

Important constructor options:

| Option | Purpose |
|---|---|
| `store` | `MemoryStore`, `SqliteStore`, or a custom `TokenStore` |
| `mailer` | Object implementing `send(MailMessage)` |
| `verify_url_base` | Public HTTPS confirmation URL |
| `identity_provider` | Dynamic user lookup and authorization |
| `allowed_emails` | Static login allowlist |
| `admin_emails` | Static administrator list |
| `allow_anyone` | Permit every syntactically valid email |
| `code_ttl` | Login request lifetime in seconds |
| `rate_max` | Maximum requests per rate window |
| `rate_window` | Login request rate window in seconds |
| `confirm_max_attempts` | Maximum code attempts per email token |
| `rate_namespace` | Prefix isolating counters for multiple flows sharing one store; login defaults to `login` and email verification to `verification` |
| `login_sender_id` | Sender identifier passed to the mail service |
| `login_mail_priority` | Priority passed to the mail service |

Core methods:

```python
login = core.start_login(
    "alice@example.com",
    captcha_given="AB12",
    captcha_expected="AB12",
    client_ip="203.0.113.10",
)
print(login.user_code)

context = core.confirm_context(token)       # no state change
core.confirm(token, login.user_code)        # approves request
result = core.poll_status(login.request_id) # consumes approval once
```

### Flask adapter

Register the blueprint:

```python
auth = EmailAuth(
    core,
    require_captcha=True,
    trust_proxy_headers=False,
)
app.register_blueprint(auth.blueprint(url_prefix="/api/auth"))
```

Host-facing methods and decorators:

```python
auth.is_authenticated()
auth.current_user()
auth.is_admin()
auth.logout()

@auth.login_required
@auth.admin_required
```

Blueprint endpoints:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/captcha` | Return CAPTCHA image and bind answer to session |
| `POST` | `/request` | Start login and return the device code |
| `GET` | `/verify?token=...` | Render side-effect-free confirmation page |
| `POST` | `/verify/confirm` | Confirm with email token and device code |
| `GET` | `/status` | Poll and establish the waiting-device session |
| `GET`/`POST` | `/logout` | Clear authentication state |
| `GET` | `/state` | Return login state for a frontend |

The `EmailVerifier` blueprint exposes the same CAPTCHA/request/verify/confirm
shape under its configured prefix. Its status endpoint returns `verified`.
The host reads the result non-destructively with `verified_email()`, performs
validation and persistence, then calls `consume_verified_email()` in the same
waiting-browser session only after success.

## Mail delivery

### `ConsoleMailer`

Prints messages and stores the last message. Development and tests only.

### `SmtpMailer`

Sends synchronously through SMTP and raises `MailDeliveryError` on failure:

```python
from maglink import SmtpMailer

mailer = SmtpMailer(
    host="smtp.example.com",
    port=465,
    username="mailer@example.com",
    password=os.environ["SMTP_PASSWORD"],
    sender="mailer@example.com",
)
```

Implicit TLS is selected by default for port 465 and STARTTLS for port 587.
Plain SMTP is rejected unless explicitly enabled.

### `HttpMailer`

Submits structured JSON messages to a durable HTTP mail service such as
MailDispatch. It sends the API key as a Bearer token and forwards the
`Idempotency-Key` header.

## Token stores

### `MemoryStore`

Use for tests and single-process development. State is lost on restart and is
not shared between workers.

### `SqliteStore`

Use for small deployments that need persistence and multiple web processes:

```python
store = SqliteStore("data/maglink.db")
```

For larger deployments, implement the `TokenStore` protocol with a shared
transactional database or Redis. `set_status()` must be an atomic
compare-and-set operation, and `incr_rate()` must be atomic.

## Frontend request example

```javascript
const request = await fetch("/api/auth/request", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({email, captcha}),
});
const {user_code} = await request.json();
showDeviceCode(user_code);

const timer = setInterval(async () => {
  const response = await fetch("/api/auth/status");
  const result = await response.json();
  if (result.status === "approved") {
    clearInterval(timer);
    location.href = "/";
  }
}, 1500);
```

## Production checklist

- Use HTTPS for the application and `verify_url_base`.
- Use a strong random Flask secret from the environment.
- Set `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, and an appropriate
  `SESSION_COOKIE_SAMESITE` policy.
- Never use `ConsoleMailer` in production.
- Use a persistent/shared token store for multi-process deployments.
- Keep login eligibility in a server-side identity provider.
- Do not put the device code in the email.
- Do not make the confirmation `GET` endpoint change state.
- Trust proxy headers only behind correctly configured trusted proxies.
- Protect MailDispatch API keys and grant only the required scopes.
- Apply recipient policy and sender restrictions in MailDispatch.
- Monitor `maglink.audit` and mail delivery failures.

## Agent skill

This repository includes an Agent Skills-compatible guide at:

```text
.agents/skills/maglink-email-login/SKILL.md
```

It tells coding agents how to implement maglink email login using a
MailDispatch API key without weakening the device-confirmation flow.

## License

MIT. See the `LICENSE` file.
