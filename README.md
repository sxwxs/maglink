# maglink

Email **magic-link** authentication with **device-flow confirmation**.

The classic magic-link flaw: clicking the emailed link logs in whoever's session
minted it — so a prefetched, leaked, or forwarded link silently authenticates a
session. maglink fixes this: the link only opens a **side-effect-free confirm
page** showing a short `user_code`; a session is authenticated only after a
deliberate POST-confirm **and** only for the same device that started the flow.

- Framework-agnostic core (`AuthCore`) — zero hard dependencies.
- Optional Flask adapter (`EmailAuth`) — `pip install maglink[flask]`.
- Pluggable store (`MemoryStore`, `SqliteStore` default; implement `TokenStore`
  for Redis) — survives restarts and multiple workers.
- Non-blocking SMTP, rate limiting, dependency-free SVG captcha.

## Flow

1. `POST /request` → mint `request_id` (bound to browser session), `user_code`
   (shown on the waiting device), `verify_token` (emailed in the link).
2. Email link → `GET /verify` renders a confirm page (no state change).
3. User compares the code, clicks → `POST /verify/confirm` approves the request.
4. Waiting device `GET /status` (polling) sees `approved` → session established.

Token (email ownership) and user_code (same-session intent) are independent;
both are required.

## Flask usage

```python
from flask import Flask
from maglink import AuthCore, SqliteStore, SmtpMailer
from maglink.flask import EmailAuth

core = AuthCore(
    store=SqliteStore("auth.db"),
    mailer=SmtpMailer(host="smtp.example.com", port=465,
                      username="me@example.com", password=os.environ["SMTP_PASS"]),
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
| POST | `/verify/confirm` | `{token}` → approve the pending request |
| GET | `/status` | waiting device polls; on approval sets session |
| GET/POST | `/logout` | clear session |
| GET | `/state` | `{logged_in, email, is_admin}` |

## Security notes

- Provide a strong Flask `secret_key` from the environment.
- `verify_url_base` must be HTTPS in production.
- Captcha is a light anti-automation gate, not a strong bot defense; it pairs
  with rate limiting.
- SMTP password via env, never committed.

MIT.
