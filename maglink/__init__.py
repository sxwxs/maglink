"""maglink — email magic-link auth with device-flow confirmation.

Core (`AuthCore`) is framework-agnostic. The Flask adapter (`EmailAuth`) is
imported lazily so installing without Flask still works for the core/tests.
"""

from .core import AuthCore, LoginRequest, AuthError, RateLimited
from .stores import TokenStore, MemoryStore, SqliteStore
from .mailer import Mailer, SmtpMailer, ConsoleMailer
from .captcha import Captcha

__all__ = [
    "AuthCore",
    "LoginRequest",
    "AuthError",
    "RateLimited",
    "TokenStore",
    "MemoryStore",
    "SqliteStore",
    "Mailer",
    "SmtpMailer",
    "ConsoleMailer",
    "Captcha",
    "EmailAuth",
]


def __getattr__(name):
    # Lazy: only pull in the Flask adapter (and Flask itself) on demand.
    if name == "EmailAuth":
        from .flask import EmailAuth

        return EmailAuth
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
