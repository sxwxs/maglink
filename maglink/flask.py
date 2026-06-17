"""Flask adapter.

Wraps :class:`maglink.core.AuthCore`, binding the device-flow ``request_id`` and
captcha answer to Flask's signed-cookie session. Exposes the public host API:
``is_authenticated`` / ``current_user`` / ``is_admin`` / ``login_required`` and a
blueprint to register.

The host app touches none of the session keys directly — only these methods.
"""

from __future__ import annotations

import functools
import html
from typing import Optional

from flask import (
    Blueprint,
    current_app,
    jsonify,
    request,
    session,
)

from .core import AuthCore, AuthError, RateLimited

_SESSION_USER = "_maglink_user"
_SESSION_REQ = "_maglink_request_id"
_SESSION_CAPTCHA = "_maglink_captcha"


class EmailAuth:
    def __init__(self, core: AuthCore, *, require_captcha: bool = True) -> None:
        self.core = core
        self.require_captcha = require_captcha

    # ---- host-facing API -------------------------------------------------

    def is_authenticated(self, req=None) -> bool:
        return bool(session.get(_SESSION_USER))

    def current_user(self, req=None) -> Optional[dict]:
        return session.get(_SESSION_USER)

    def is_admin(self, req=None) -> bool:
        u = session.get(_SESSION_USER)
        return bool(u and u.get("is_admin"))

    def login_required(self, fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not self.is_authenticated():
                return jsonify({"ok": False, "error": "auth_required"}), 401
            return fn(*args, **kwargs)

        return wrapper

    def admin_required(self, fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not self.is_admin():
                return jsonify({"ok": False, "error": "admin_required"}), 403
            return fn(*args, **kwargs)

        return wrapper

    def logout(self) -> None:
        session.pop(_SESSION_USER, None)
        session.pop(_SESSION_REQ, None)

    # ---- blueprint -------------------------------------------------------

    def blueprint(self, name: str = "maglink", url_prefix: str = "/api/auth") -> Blueprint:
        bp = Blueprint(name, __name__, url_prefix=url_prefix)

        @bp.get("/captcha")
        def captcha():
            code, svg = self.core.new_captcha()
            session[_SESSION_CAPTCHA] = code
            return jsonify({"ok": True, "image": svg})

        @bp.post("/request")
        def request_login():
            data = request.get_json(silent=True) or request.form
            email = (data.get("email") or "").strip()
            captcha_given = data.get("captcha") or ""
            captcha_expected = session.pop(_SESSION_CAPTCHA, "")
            try:
                lr = self.core.start_login(
                    email,
                    captcha_given=captcha_given,
                    captcha_expected=captcha_expected,
                    client_ip=_client_ip(),
                    require_captcha=self.require_captcha,
                )
            except RateLimited as e:
                return jsonify({"ok": False, "error": "rate_limited", "message": str(e)}), 429
            except AuthError as e:
                return jsonify({"ok": False, "error": "invalid", "message": str(e)}), 400

            # Bind this pending request to THIS browser session. The waiting
            # device is identified by this server-side request_id, not by a
            # value the client could forge.
            session[_SESSION_REQ] = lr.request_id
            return jsonify({"ok": True, "user_code": lr.user_code})

        @bp.get("/verify")
        def verify_page():
            # Side-effect-free render of the confirm page. Safe for link prefetch.
            token = request.args.get("token", "")
            ctx = self.core.confirm_context(token)
            return _confirm_html(token, ctx), 200, {"Content-Type": "text/html; charset=utf-8"}

        @bp.post("/verify/confirm")
        def verify_confirm():
            data = request.get_json(silent=True) or request.form
            token = data.get("token") or request.args.get("token", "")
            try:
                res = self.core.confirm(token)
            except AuthError as e:
                return jsonify({"ok": False, "error": "invalid", "message": str(e)}), 400
            return jsonify({"ok": True, "email": res["email"]})

        @bp.get("/status")
        def status():
            rid = session.get(_SESSION_REQ, "")
            res = self.core.poll_status(rid)
            if res["status"] == "approved":
                session[_SESSION_USER] = {"email": res["email"], "is_admin": res["is_admin"]}
                session.pop(_SESSION_REQ, None)
                return jsonify({"ok": True, "status": "approved", "email": res["email"]})
            return jsonify({"ok": True, "status": res["status"]})

        @bp.route("/logout", methods=["GET", "POST"])
        def logout():
            self.logout()
            return jsonify({"ok": True})

        @bp.get("/state")
        def state():
            u = self.current_user()
            return jsonify({
                "ok": True,
                "logged_in": bool(u),
                "email": u.get("email") if u else None,
                "is_admin": bool(u and u.get("is_admin")),
            })

        return bp


def _client_ip() -> str:
    # Honor a single proxy hop if present; fall back to remote_addr.
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def _confirm_html(token: str, ctx: dict) -> str:
    if not ctx.get("valid"):
        return (
            "<!doctype html><meta charset=utf-8><title>Sign-in</title>"
            "<body style='font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>"
            "<h1>Link invalid or expired</h1>"
            "<p>This sign-in link is no longer valid. Please start again.</p>"
        )
    code = html.escape(ctx["user_code"])
    email = html.escape(ctx["email"])
    safe_token = html.escape(token)
    done = (
        "<p style='color:#137333'>Already confirmed — return to the device where you "
        "started signing in.</p>"
        if ctx.get("already_approved")
        else ""
    )
    # Confirm requires a deliberate POST. GET (prefetch) never authenticates.
    return f"""<!doctype html><meta charset=utf-8><title>Confirm sign-in</title>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h1>Confirm sign-in</h1>
<p>You're signing in as <b>{email}</b>.</p>
<p>The device where you started should show this code:</p>
<p style="font-size:2rem;font-weight:bold;letter-spacing:.1em">{code}</p>
<p>If it matches, confirm below. If you didn't start this, close this page.</p>
{done}
<button id="go" style="font-size:1rem;padding:.6rem 1.2rem;cursor:pointer">Confirm sign-in</button>
<p id="msg"></p>
<script>
document.getElementById('go').onclick = async () => {{
  const r = await fetch('verify/confirm?token={safe_token}', {{method:'POST'}});
  const j = await r.json();
  document.getElementById('msg').textContent =
    j.ok ? 'Confirmed. Return to your other device.' : (j.message || 'Failed.');
  if (j.ok) document.getElementById('go').disabled = true;
}};
</script>
"""
