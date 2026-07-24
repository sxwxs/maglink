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
    jsonify,
    request,
    session,
)

from .core import AuthCore, AuthError, EmailVerificationCore, RateLimited

_SESSION_USER = "_maglink_user"
_SESSION_REQ = "_maglink_request_id"
_SESSION_CAPTCHA = "_maglink_captcha"
_SESSION_VERIFY_REQ = "_maglink_verify_request_id"
_SESSION_VERIFY_CAPTCHA = "_maglink_verify_captcha"
_SESSION_VERIFIED_EMAIL = "_maglink_verified_email"


class EmailAuth:
    def __init__(
        self,
        core: AuthCore,
        *,
        require_captcha: bool = True,
        trust_proxy_headers: bool = False,
    ) -> None:
        self.core = core
        self.require_captcha = require_captcha
        self.trust_proxy_headers = trust_proxy_headers

    # ---- host-facing API -------------------------------------------------

    def is_authenticated(self, req=None) -> bool:
        return self.current_user(req) is not None

    def current_user(self, req=None) -> Optional[dict]:
        stored = session.get(_SESSION_USER)
        if not stored:
            return None
        identity = self.core.get_identity(stored.get("email", ""))
        if identity is None or not identity.active:
            session.pop(_SESSION_USER, None)
            return None
        # Authorization is refreshed from the provider on every request, so a
        # disabled or demoted database user does not retain stale privileges.
        return {
            "id": identity.id,
            "email": identity.email,
            "roles": list(identity.roles),
            "claims": identity.claims,
            "is_admin": identity.is_admin,
        }

    def is_admin(self, req=None) -> bool:
        user = self.current_user(req)
        return bool(user and user.get("is_admin"))

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
                    client_ip=self._client_ip(),
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
            user_code = data.get("user_code") or data.get("code") or ""
            try:
                res = self.core.confirm(token, user_code)
            except AuthError as e:
                return jsonify({"ok": False, "error": "invalid", "message": str(e)}), 400
            return jsonify({"ok": True, "email": res["email"]})

        @bp.get("/status")
        def status():
            rid = session.get(_SESSION_REQ, "")
            res = self.core.poll_status(rid)
            if res["status"] == "approved":
                session[_SESSION_USER] = {
                    "id": res.get("identity_id", res["email"]),
                    "email": res["email"],
                    "roles": res.get("roles", []),
                    "claims": res.get("claims", {}),
                    "is_admin": res["is_admin"],
                }
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

    def _client_ip(self) -> str:
        if self.trust_proxy_headers:
            fwd = request.headers.get("X-Forwarded-For", "")
            if fwd:
                return fwd.split(",")[0].strip()
        return request.remote_addr or ""


class EmailVerifier:
    """Flask adapter for email ownership verification without authentication.

    A successfully verified address is kept in the waiting browser's signed
    session until the host application consumes it exactly once.
    """

    def __init__(
        self,
        core: EmailVerificationCore,
        *,
        require_captcha: bool = True,
        trust_proxy_headers: bool = False,
    ) -> None:
        self.core = core
        self.require_captcha = require_captcha
        self.trust_proxy_headers = trust_proxy_headers

    def verified_email(self) -> Optional[str]:
        """Return the waiting session's verified email without consuming it."""
        email = session.get(_SESSION_VERIFIED_EMAIL)
        return str(email) if email else None

    def consume_verified_email(self) -> Optional[str]:
        """Consume and return the waiting session's verified email exactly once."""
        email = session.pop(_SESSION_VERIFIED_EMAIL, None)
        return str(email) if email else None

    def blueprint(
        self,
        name: str = "maglink_verify",
        url_prefix: str = "/api/email-verification",
    ) -> Blueprint:
        bp = Blueprint(name, __name__, url_prefix=url_prefix)

        @bp.get("/captcha")
        def captcha():
            code, svg = self.core.new_captcha()
            session[_SESSION_VERIFY_CAPTCHA] = code
            return jsonify({"ok": True, "image": svg})

        @bp.post("/request")
        def request_verification():
            data = request.get_json(silent=True) or request.form
            email = (data.get("email") or "").strip()
            captcha_given = data.get("captcha") or ""
            captcha_expected = session.pop(_SESSION_VERIFY_CAPTCHA, "")
            session.pop(_SESSION_VERIFIED_EMAIL, None)
            try:
                result = self.core.start_login(
                    email,
                    captcha_given=captcha_given,
                    captcha_expected=captcha_expected,
                    client_ip=self._client_ip(),
                    require_captcha=self.require_captcha,
                )
            except RateLimited as exc:
                return jsonify({"ok": False, "error": "rate_limited", "message": str(exc)}), 429
            except AuthError as exc:
                return jsonify({"ok": False, "error": "invalid", "message": str(exc)}), 400
            session[_SESSION_VERIFY_REQ] = result.request_id
            return jsonify({"ok": True, "user_code": result.user_code})

        @bp.get("/verify")
        def verify_page():
            token = request.args.get("token", "")
            ctx = self.core.confirm_context(token)
            return _confirm_html(token, ctx, action="verify your email"), 200, {
                "Content-Type": "text/html; charset=utf-8"
            }

        @bp.post("/verify/confirm")
        def verify_confirm():
            data = request.get_json(silent=True) or request.form
            token = data.get("token") or request.args.get("token", "")
            user_code = data.get("user_code") or data.get("code") or ""
            try:
                result = self.core.confirm(token, user_code)
            except RateLimited as exc:
                return jsonify({"ok": False, "error": "rate_limited", "message": str(exc)}), 429
            except AuthError as exc:
                return jsonify({"ok": False, "error": "invalid", "message": str(exc)}), 400
            return jsonify({"ok": True, "email": result["email"]})

        @bp.get("/status")
        def status():
            request_id = session.get(_SESSION_VERIFY_REQ, "")
            result = self.core.poll_status(request_id)
            if result["status"] == "verified":
                session[_SESSION_VERIFIED_EMAIL] = result["email"]
                session.pop(_SESSION_VERIFY_REQ, None)
                return jsonify({"ok": True, "status": "verified", "email": result["email"]})
            return jsonify({"ok": True, "status": result["status"]})

        return bp

    def _client_ip(self) -> str:
        if self.trust_proxy_headers:
            forwarded = request.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()
        return request.remote_addr or ""


def _confirm_html(token: str, ctx: dict, action: str = "sign in") -> str:
    if not ctx.get("valid"):
        return (
            "<!doctype html><meta charset=utf-8><title>Sign-in</title>"
            "<body style='font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem'>"
            "<h1>Link invalid or expired</h1>"
            "<p>This sign-in link is no longer valid. Please start again.</p>"
        )
    email = html.escape(ctx["email"])
    safe_token = html.escape(token)
    done = (
        "<p style='color:#137333'>Already confirmed — return to the device where you "
        "started signing in.</p>"
        if ctx.get("already_approved")
        else ""
    )
    # Confirm requires a deliberate POST. GET (prefetch) never authenticates.
    safe_action = html.escape(action)
    return f"""<!doctype html><meta charset=utf-8><title>Confirm</title>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h1>Confirm</h1>
<p>Continue as <b>{email}</b> to {safe_action}.</p>
<p>Enter the code shown on the device where you started.</p>
{done}
<form id="confirm-form">
  <input id="token" type="hidden" value="{safe_token}">
  <input id="code" name="user_code" inputmode="text" autocomplete="one-time-code"
         style="font-size:1.25rem;padding:.5rem;width:10rem;text-transform:uppercase"
         aria-label="Sign-in code" required autofocus>
  <button id="go" style="font-size:1rem;padding:.6rem 1.2rem;cursor:pointer">Confirm sign-in</button>
</form>
<p id="msg"></p>
<script>
document.getElementById('confirm-form').onsubmit = async (event) => {{
  event.preventDefault();
  const r = await fetch('verify/confirm', {{
    method:'POST',
    headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{
      token: document.getElementById('token').value,
      user_code: document.getElementById('code').value
    }})
  }});
  const j = await r.json();
  document.getElementById('msg').textContent =
    j.ok ? 'Confirmed. Return to your other device.' : (j.message || 'Failed.');
  if (j.ok) document.getElementById('go').disabled = true;
}};
</script>
"""
