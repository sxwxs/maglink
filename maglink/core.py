"""Framework-agnostic device-flow auth logic.

The flow (see DESIGN.md §11.2):

1. ``start_login``  -> mint request_id (caller binds to the browser session),
   user_code (shown on the waiting device), verify_token (emailed in the link).
   Emails the link. Returns the user_code to display.
2. ``confirm_context``  -> SIDE-EFFECT-FREE lookup for rendering the confirm page
   (shows the expected user_code). Safe for link prefetch.
3. ``confirm``  -> the deliberate human action; marks the request approved.
4. ``poll_status``  -> the waiting device polls by its request_id; once approved,
   atomically consumes the request and returns the authenticated email.

The token (email ownership) and the user_code (same-session intent) are
independent; both are required, so a prefetched or leaked link cannot log
anyone in on its own.
"""

from __future__ import annotations

import logging
import re
import secrets
import time
from dataclasses import dataclass
from typing import Iterable, Optional

from .captcha import Captcha
from .mailer import Mailer
from .stores import StoredRequest, TokenStore

log = logging.getLogger("maglink.audit")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# user_code alphabet: unambiguous, uppercase
_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"


class AuthError(Exception):
    """User-facing auth failure (bad captcha, not allowed, expired, etc.)."""


class RateLimited(AuthError):
    pass


@dataclass
class LoginRequest:
    request_id: str
    user_code: str
    # verify_token is intentionally NOT exposed to the waiting device; it only
    # travels via email.


def _now() -> float:
    return time.time()


def _gen_user_code(n: int = 6) -> str:
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(n))
    # group as XXX-XXX for readability
    mid = n // 2
    return f"{raw[:mid]}-{raw[mid:]}"


class AuthCore:
    def __init__(
        self,
        store: TokenStore,
        mailer: Mailer,
        *,
        verify_url_base: str,
        allowed_emails: Optional[Iterable[str]] = None,
        allow_anyone: bool = False,
        admin_emails: Optional[Iterable[str]] = None,
        code_ttl: float = 600.0,
        rate_max: int = 5,
        rate_window: float = 3600.0,
        captcha: Optional[Captcha] = None,
        email_subject: str = "Confirm your sign-in",
    ) -> None:
        self.store = store
        self.mailer = mailer
        self.verify_url_base = verify_url_base.rstrip("/")
        self.allowed = {e.lower() for e in (allowed_emails or [])}
        self.allow_anyone = allow_anyone
        self.admins = {e.lower() for e in (admin_emails or [])}
        self.code_ttl = code_ttl
        self.rate_max = rate_max
        self.rate_window = rate_window
        self.captcha = captcha or Captcha()
        self.email_subject = email_subject

    # ---- helpers ---------------------------------------------------------

    def is_email_allowed(self, email: str) -> bool:
        return self.allow_anyone or email.lower() in self.allowed

    def is_admin(self, email: str) -> bool:
        return email.lower() in self.admins

    def new_captcha(self) -> tuple[str, str]:
        """Return ``(code, svg_data_uri)``; caller stores the code in session."""
        return self.captcha.generate()

    # ---- step 1: start ---------------------------------------------------

    def start_login(
        self,
        email: str,
        *,
        captcha_given: str = "",
        captcha_expected: str = "",
        client_ip: str = "",
        require_captcha: bool = True,
    ) -> LoginRequest:
        email = (email or "").strip().lower()
        now = _now()
        self.store.purge_expired(now)

        # Rate limit FIRST and uniformly — before allowlist/validity checks — so
        # response timing/shape can't be used to enumerate valid emails.
        self._check_rate(f"ip:{client_ip}", now)
        self._check_rate(f"email:{email}", now)

        if not _EMAIL_RE.match(email):
            raise AuthError("Invalid email address.")
        if require_captcha and not Captcha.check(captcha_expected, captcha_given):
            raise AuthError("Incorrect captcha.")

        request_id = secrets.token_urlsafe(24)
        verify_token = secrets.token_urlsafe(32)
        user_code = _gen_user_code()

        # Only persist + email for allowed addresses, but DO NOT change the
        # response for disallowed ones (uniform success-looking result) to avoid
        # leaking which emails are permitted.
        if self.is_email_allowed(email):
            self.store.put(
                StoredRequest(
                    request_id=request_id,
                    email=email,
                    user_code=user_code,
                    verify_token=verify_token,
                    status="pending",
                    created_at=now,
                    expires_at=now + self.code_ttl,
                )
            )
            link = f"{self.verify_url_base}?token={verify_token}"
            body = (
                f"Someone requested a sign-in for this email.\n\n"
                f"Open this link to continue:\n{link}\n\n"
                f"Then confirm the code shown on the device where you started "
                f"signing in. The code is: {user_code}\n\n"
                f"If you didn't request this, ignore this email.\n"
                f"This link expires in {int(self.code_ttl // 60)} minutes."
            )
            self.mailer.send(email, self.email_subject, body)
            log.info("LOGIN_REQUEST email=%s ip=%s request_id=%s", email, client_ip, request_id)
        else:
            log.info("LOGIN_REQUEST_DENIED email=%s ip=%s", email, client_ip)

        # request_id + user_code returned regardless; for a disallowed email the
        # request_id simply never becomes approvable.
        return LoginRequest(request_id=request_id, user_code=user_code)

    def _check_rate(self, key: str, now: float) -> None:
        count = self.store.incr_rate(key, now, self.rate_window)
        if count > self.rate_max:
            log.info("RATE_LIMITED key=%s count=%s", key, count)
            raise RateLimited("Too many requests. Try again later.")

    # ---- step 2: confirm page context (NO side effects) ------------------

    def confirm_context(self, verify_token: str) -> dict:
        """Data to render the confirm page. Side-effect-free (safe for prefetch)."""
        now = _now()
        req = self.store.get_by_token(verify_token or "")
        if req is None or req.expires_at < now or req.status == "consumed":
            return {"valid": False}
        return {
            "valid": True,
            "email": req.email,
            "user_code": req.user_code,
            "already_approved": req.status == "approved",
        }

    # ---- step 3: confirm (the deliberate action) -------------------------

    def confirm(self, verify_token: str) -> dict:
        now = _now()
        req = self.store.get_by_token(verify_token or "")
        if req is None or req.expires_at < now:
            raise AuthError("This sign-in link is invalid or has expired.")
        if req.status == "consumed":
            raise AuthError("This sign-in has already been completed.")
        # pending -> approved, atomically (idempotent if already approved).
        if req.status == "pending":
            if not self.store.set_status(req.request_id, "pending", "approved"):
                raise AuthError("Could not confirm; please retry.")
        log.info("LOGIN_CONFIRMED email=%s request_id=%s", req.email, req.request_id)
        return {"email": req.email, "user_code": req.user_code}

    # ---- step 4: waiting device polls ------------------------------------

    def poll_status(self, request_id: str) -> dict:
        """Called by the waiting device. On 'approved', atomically completes and
        returns the email so the adapter can establish the session."""
        now = _now()
        req = self.store.get(request_id or "")
        if req is None or req.expires_at < now:
            return {"status": "expired"}
        if req.status == "pending":
            return {"status": "pending"}
        if req.status == "approved":
            # Consume single-use: approved -> consumed, atomically. Only the
            # winner of the CAS gets to complete the login.
            if self.store.set_status(request_id, "approved", "consumed"):
                self.store.delete(request_id)
                log.info("LOGIN_SUCCESS email=%s request_id=%s", req.email, request_id)
                return {"status": "approved", "email": req.email, "is_admin": self.is_admin(req.email)}
            return {"status": "pending"}
        return {"status": "expired"}
