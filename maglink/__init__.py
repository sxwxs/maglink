"""maglink — email magic-link auth with device-flow confirmation.

Core (`AuthCore`) is framework-agnostic. The Flask adapter (`EmailAuth`) is
imported lazily so installing without Flask still works for the core/tests.
"""

from .core import AuthCore, EmailVerificationCore, LoginRequest, AuthError, RateLimited
from .identity import Identity, IdentityProvider, StaticIdentityProvider
from .stores import TokenStore, MemoryStore, SqliteStore
from .mailer import (
    MailDeliveryError,
    MailMessage,
    MailPriority,
    MailReceipt,
    Mailer,
    SmtpMailer,
    ConsoleMailer,
    HttpMailer,
)
from .captcha import Captcha

__all__ = [
    "AuthCore",
    "EmailVerificationCore",
    "LoginRequest",
    "AuthError",
    "RateLimited",
    "Identity",
    "IdentityProvider",
    "StaticIdentityProvider",
    "TokenStore",
    "MemoryStore",
    "SqliteStore",
    "MailDeliveryError",
    "MailMessage",
    "MailPriority",
    "MailReceipt",
    "Mailer",
    "SmtpMailer",
    "ConsoleMailer",
    "HttpMailer",
    "Captcha",
    "EmailAuth",
    "EmailVerifier",
]


def __getattr__(name):
    # Lazy: only pull in the Flask adapter (and Flask itself) on demand.
    if name in {"EmailAuth", "EmailVerifier"}:
        from .flask import EmailAuth, EmailVerifier

        return {"EmailAuth": EmailAuth, "EmailVerifier": EmailVerifier}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
