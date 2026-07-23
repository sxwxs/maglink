import json

from maglink import HttpMailer, MailMessage, MailPriority


def test_http_mailer_submits_structured_message(monkeypatch):
    captured = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self):
            return b'{"ok":true,"message_id":"msg_1","status":"queued"}'

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    mailer = HttpMailer(
        "https://mail.example.test/api/v1/messages",
        "md_live_secret",
        sender_id="system",
    )
    receipt = mailer.send(
        MailMessage(
            to=("alice@example.test",),
            subject="Sign in",
            text="Body",
            priority=MailPriority.AUTHENTICATION,
            purpose="authentication",
            idempotency_key="login-1",
        )
    )
    request = captured["request"]
    payload = json.loads(request.data)
    assert request.get_header("Authorization") == "Bearer md_live_secret"
    assert request.get_header("Idempotency-key") == "login-1"
    assert payload["sender_id"] == "system"
    assert payload["priority"] == 1000
    assert receipt.message_id == "msg_1"
