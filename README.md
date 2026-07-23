# maglink

Email **magic-link** authentication with **device-flow confirmation**.

The classic magic-link flaw: clicking the emailed link logs in whoever's session
minted it — so a prefetched, leaked, or forwarded link silently authenticates a
session. maglink fixes this: the link only opens a **side-effect-free confirm
page** that asks for the short `user_code` shown on the waiting device; a session
is authenticated only after a deliberate POST-confirm **and** only for the same
device that started the flow.

- Framework-agnostic core (`AuthCore`) — zero hard dependencies.
- Optional Flask adapter (`EmailAuth`) — `pip install maglink[flask]`.
- Dynamic `IdentityProvider` support plus a compatibility static allowlist.
- In-memory and SQLite stores for pending auth state and rate limits.
- Structured mail messages with console, SMTP, HTTP, or host-injected delivery.
- Audit logging, rate limiting, confirmation-attempt limits, dependency-free SVG captcha.

## Flow

1. `POST /request` → mint `request_id` (bound to browser session), `user_code`
   (shown on the waiting device), `verify_token` (emailed in the link).
2. Email link → `GET /verify` renders a confirm page (no state change, no code
   disclosure).
3. User enters the waiting-device code → `POST /verify/confirm` approves the
   request.
4. Waiting device `GET /status` (polling) sees `approved` → session established.

Token (email ownership) and user_code (same-session intent) are independent;
both are required.

## Flask usage

```python
from flask import Flask
from maglink import AuthCore, SqliteStore, HttpMailer
from maglink.flask import EmailAuth

core = AuthCore(
    store=SqliteStore("auth.db"),
    mailer=HttpMailer(
        "https://mail.example.com/api/v1/messages",
        os.environ["MAIL_API_KEY"],
        sender_id="system",
    ),
    verify_url_base="https://notes.example.com/api/auth/verify",
    allowed_emails=["me@example.com"],
    admin_emails=["me@example.com"],
)
auth = EmailAuth(core)

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.register_blueprint(auth.blueprint(url_prefix="/api/auth"))

@app.get("/admin")
@auth.admin_required
def admin(): ...
```

Host API: `auth.is_authenticated()`, `auth.current_user()`, `auth.is_admin()`,
`@auth.login_required`, `@auth.admin_required`, `auth.logout()`.

## Endpoints (blueprint)

| method | path | purpose |
|---|---|---|
| GET | `/captcha` | captcha image (data URI), sets answer in session |
| POST | `/request` | `{email, captcha}` → emails link, returns `{user_code}` |
| GET | `/verify?token=` | confirm page (side-effect-free) |
| POST | `/verify/confirm` | `{token, user_code}` → approve the pending request |
| GET | `/status` | waiting device polls; on approval sets session |
| GET/POST | `/logout` | clear session |
| GET | `/state` | `{logged_in, email, is_admin}` |

## Security notes

- Provide a strong Flask `secret_key` from the environment.
- `verify_url_base` must be HTTPS in production.
- `MemoryStore` is process-local and intended for tests/single-process apps.
  Use `SqliteStore` or provide your own `TokenStore` for persistent deployments.
- `HttpMailer` submits authentication messages with priority, purpose, metadata,
  and an idempotency key. A host can instead inject a direct durable queue mailer.
- The Flask adapter ignores `X-Forwarded-For` by default. Use
  `EmailAuth(core, trust_proxy_headers=True)` only behind trusted proxy
  middleware/configuration.
- Captcha is a light anti-automation gate, not a strong bot defense; it pairs
  with rate limiting.
- SMTP password via env, never committed.

MIT.
