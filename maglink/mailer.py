"""Email delivery. ``Mailer`` is the interface; the core only calls ``send``.

``SmtpMailer`` sends in a background thread so a slow/unreachable SMTP server
never stalls the HTTP request that triggered it. ``ConsoleMailer`` prints the
link (dev/tests) and records the last message for assertions.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from typing import Optional, Protocol

log = logging.getLogger("maglink.mailer")


class Mailer(Protocol):
    def send(self, to: str, subject: str, body: str) -> None: ...


class ConsoleMailer:
    """Prints emails instead of sending. Keeps the last message for tests."""

    def __init__(self) -> None:
        self.last: Optional[dict] = None

    def send(self, to: str, subject: str, body: str) -> None:
        self.last = {"to": to, "subject": subject, "body": body}
        print(f"\n--- maglink email ---\nTo: {to}\nSubject: {subject}\n\n{body}\n---------------------\n")


class SmtpMailer:
    def __init__(
        self,
        host: str,
        port: int = 465,
        username: str = "",
        password: str = "",
        sender: str = "",
        use_ssl: Optional[bool] = None,
        starttls: bool = False,
        timeout: float = 15.0,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sender = sender or username
        # Default to implicit SSL on the conventional SSL port unless told otherwise.
        self.use_ssl = (port == 465) if use_ssl is None else use_ssl
        self.starttls = starttls
        self.timeout = timeout

    def send(self, to: str, subject: str, body: str) -> None:
        # Fire-and-forget: failures are logged, not surfaced to the user, so the
        # response (and the rate-limit-uniform behaviour) is independent of SMTP.
        t = threading.Thread(target=self._send_blocking, args=(to, subject, body), daemon=True)
        t.start()

    def _send_blocking(self, to: str, subject: str, body: str) -> None:
        try:
            msg = EmailMessage()
            msg["From"] = self.sender
            msg["To"] = to
            msg["Subject"] = subject
            msg.set_content(body)

            if self.use_ssl:
                ctx = ssl.create_default_context()
                with smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout, context=ctx) as s:
                    if self.username:
                        s.login(self.username, self.password)
                    s.send_message(msg)
            else:
                with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as s:
                    if self.starttls:
                        s.starttls(context=ssl.create_default_context())
                    if self.username:
                        s.login(self.username, self.password)
                    s.send_message(msg)
            log.info("EMAIL_SENT to=%s", to)
        except Exception as e:  # noqa: BLE001 - log and swallow; never crash the request thread
            log.error("EMAIL_SEND_FAILED to=%s err=%s", to, e)
