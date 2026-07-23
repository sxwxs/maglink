"""Pluggable mail delivery for maglink.

The core emits a structured :class:`MailMessage`. Built-in implementations can
print, submit directly to SMTP, or enqueue through an HTTP mail service. Custom
hosts may inject any object implementing ``Mailer.send(message)``.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import IntEnum
from email.message import EmailMessage
from typing import Any, Optional, Protocol, Union

log = logging.getLogger("maglink.mailer")


class MailPriority(IntEnum):
    BULK = 10
    NORMAL = 100
    HIGH = 500
    SYSTEM = 800
    AUTHENTICATION = 1000


@dataclass(frozen=True)
class MailMessage:
    to: tuple[str, ...]
    subject: str
    text: Optional[str] = None
    html: Optional[str] = None
    sender_id: Optional[str] = None
    reply_to: Optional[str] = None
    priority: int = int(MailPriority.NORMAL)
    purpose: str = "transactional"
    idempotency_key: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MailReceipt:
    accepted: bool
    message_id: Optional[str] = None
    status: str = "accepted"


class MailDeliveryError(RuntimeError):
    pass


class Mailer(Protocol):
    def send(self, message: MailMessage) -> MailReceipt: ...


def _coerce_message(
    message_or_to: Union[MailMessage, str],
    subject: Optional[str] = None,
    body: Optional[str] = None,
) -> MailMessage:
    """Accept the v0.1 ``send(to, subject, body)`` shape for compatibility."""
    if isinstance(message_or_to, MailMessage):
        return message_or_to
    return MailMessage(to=(message_or_to,), subject=subject or "", text=body or "")


class ConsoleMailer:
    """Print messages and retain the last one for development/tests."""

    def __init__(self) -> None:
        self.last: Optional[dict[str, Any]] = None

    def send(
        self,
        message: Union[MailMessage, str],
        subject: Optional[str] = None,
        body: Optional[str] = None,
    ) -> MailReceipt:
        msg = _coerce_message(message, subject, body)
        # Keep legacy keys so existing callers/tests continue to work.
        self.last = {
            "to": msg.to[0] if len(msg.to) == 1 else list(msg.to),
            "subject": msg.subject,
            "body": msg.text or "",
            "message": msg,
        }
        print(
            "\n--- maglink email ---\n"
            f"To: {', '.join(msg.to)}\nSubject: {msg.subject}\n"
            f"Priority: {msg.priority}\nPurpose: {msg.purpose}\n\n"
            f"{msg.text or msg.html or ''}\n---------------------\n"
        )
        return MailReceipt(accepted=True, status="printed")


class SmtpMailer:
    """Synchronous direct SMTP transport.

    Production services normally inject a durable queue mailer instead. This
    implementation is useful for small standalone applications and propagates
    failures so a login request is never reported as accepted when SMTP failed.
    """

    def __init__(
        self,
        host: str,
        port: int = 465,
        username: str = "",
        password: str = "",
        sender: str = "",
        use_ssl: Optional[bool] = None,
        starttls: Optional[bool] = None,
        timeout: float = 15.0,
        allow_plain: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender = sender or username
        self.use_ssl = (port == 465) if use_ssl is None else use_ssl
        self.starttls = (port == 587) if starttls is None else starttls
        self.timeout = timeout
        self.allow_plain = allow_plain
        if not self.use_ssl and not self.starttls and not self.allow_plain:
            raise ValueError("Plain SMTP is disabled; enable SSL/STARTTLS or set allow_plain=True")

    def send(
        self,
        message: Union[MailMessage, str],
        subject: Optional[str] = None,
        body: Optional[str] = None,
    ) -> MailReceipt:
        msg = _coerce_message(message, subject, body)
        email = EmailMessage()
        email["From"] = self.sender
        email["To"] = ", ".join(msg.to)
        email["Subject"] = msg.subject
        if msg.reply_to:
            email["Reply-To"] = msg.reply_to
        if msg.text is not None:
            email.set_content(msg.text)
        else:
            email.set_content("This message requires an HTML-capable email client.")
        if msg.html is not None:
            email.add_alternative(msg.html, subtype="html")

        try:
            if self.use_ssl:
                with smtplib.SMTP_SSL(
                    self.host,
                    self.port,
                    timeout=self.timeout,
                    context=ssl.create_default_context(),
                ) as smtp:
                    if self.username:
                        smtp.login(self.username, self.password)
                    smtp.send_message(email)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
                    smtp.ehlo()
                    if self.starttls:
                        smtp.starttls(context=ssl.create_default_context())
                        smtp.ehlo()
                    if self.username:
                        smtp.login(self.username, self.password)
                    smtp.send_message(email)
        except Exception as exc:  # noqa: BLE001 - normalize transport failures
            log.error("EMAIL_SEND_FAILED to=%s err=%s", ",".join(msg.to), exc)
            raise MailDeliveryError(str(exc)) from exc

        log.info("EMAIL_SENT to=%s", ",".join(msg.to))
        return MailReceipt(accepted=True, status="sent")


class HttpMailer:
    """Submit mail to a generic JSON HTTP endpoint such as MailDispatch."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        *,
        sender_id: Optional[str] = None,
        timeout: float = 10.0,
        extra_headers: Optional[dict[str, str]] = None,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.sender_id = sender_id
        self.timeout = timeout
        self.extra_headers = dict(extra_headers or {})

    def send(self, message: MailMessage) -> MailReceipt:
        payload = {
            "to": list(message.to),
            "subject": message.subject,
            "text": message.text,
            "html": message.html,
            "sender_id": message.sender_id or self.sender_id,
            "reply_to": message.reply_to,
            "priority": int(message.priority),
            "purpose": message.purpose,
            "metadata": message.metadata,
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self.extra_headers,
        }
        if message.idempotency_key:
            headers["Idempotency-Key"] = message.idempotency_key
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                data = json.loads(raw) if raw else {}
                if response.status < 200 or response.status >= 300:
                    raise MailDeliveryError(f"mail endpoint returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise MailDeliveryError(f"mail endpoint returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise MailDeliveryError(f"mail endpoint failed: {exc}") from exc

        if data.get("ok") is False:
            raise MailDeliveryError(data.get("error") or "mail endpoint rejected message")
        return MailReceipt(
            accepted=True,
            message_id=data.get("message_id") or data.get("id"),
            status=data.get("status", "queued"),
        )
