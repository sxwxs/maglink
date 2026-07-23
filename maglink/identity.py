"""Dynamic identity providers for maglink.

Authentication proves ownership of an email address. Authorization data (whether
that email may log in and which roles it has) comes from an ``IdentityProvider``.
Hosts backed by a database can reflect user changes without restarting maglink.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Optional, Protocol


@dataclass(frozen=True)
class Identity:
    id: str
    email: str
    active: bool = True
    roles: tuple[str, ...] = ()
    claims: dict[str, Any] = field(default_factory=dict)

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles


class IdentityProvider(Protocol):
    def get_identity(self, email: str) -> Optional[Identity]: ...

    def can_login(self, email: str) -> bool: ...


class StaticIdentityProvider:
    """Compatibility provider for the original allowlist-based API."""

    def __init__(
        self,
        *,
        allowed_emails: Optional[Iterable[str]] = None,
        admin_emails: Optional[Iterable[str]] = None,
        allow_anyone: bool = False,
    ) -> None:
        self.allowed = {e.strip().lower() for e in (allowed_emails or []) if e.strip()}
        self.admins = {e.strip().lower() for e in (admin_emails or []) if e.strip()}
        self.allow_anyone = allow_anyone

    def can_login(self, email: str) -> bool:
        email = email.strip().lower()
        # Admin membership implies login eligibility. This avoids the surprising
        # historical state where an administrator could be unable to log in.
        return self.allow_anyone or email in self.allowed or email in self.admins

    def get_identity(self, email: str) -> Optional[Identity]:
        email = email.strip().lower()
        if not self.can_login(email):
            return None
        roles = ("admin",) if email in self.admins else ("user",)
        return Identity(id=email, email=email, roles=roles)
