#!/usr/bin/env python3
"""Runnable maglink + Flask example using ConsoleMailer.

Run:
    pip install "maglink[flask]"
    export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
    export ALLOWED_EMAILS="alice@example.com"
    python examples/flask_app.py

The login email is printed in the terminal. Open its link, enter the device code
shown in the browser, then return to the browser.
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify
from maglink import AuthCore, ConsoleMailer, SqliteStore
from maglink.flask import EmailAuth

BASE_URL = os.getenv("BASE_URL", "http://127.0.0.1:5000").rstrip("/")
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

allowed_emails = [
    email.strip().lower()
    for email in os.getenv("ALLOWED_EMAILS", "alice@example.com").split(",")
    if email.strip()
]
admin_emails = [
    email.strip().lower()
    for email in os.getenv("ADMIN_EMAILS", allowed_emails[0]).split(",")
    if email.strip()
]

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=BASE_URL.startswith("https://"),
)

core = AuthCore(
    store=SqliteStore(str(DATA_DIR / "maglink.db")),
    mailer=ConsoleMailer(),
    verify_url_base=f"{BASE_URL}/api/auth/verify",
    allowed_emails=allowed_emails,
    admin_emails=admin_emails,
)
auth = EmailAuth(core, require_captcha=False)
app.register_blueprint(auth.blueprint(url_prefix="/api/auth"))


@app.get("/")
def index():
    return """<!doctype html>
<meta charset="utf-8">
<title>maglink example</title>
<body style="font:16px system-ui;max-width:36rem;margin:3rem auto">
  <h1>maglink example</h1>
  <div id="state">Loading…</div>
  <form id="login" hidden>
    <input id="email" type="email" placeholder="alice@example.com" required>
    <button>Send login email</button>
  </form>
  <div id="waiting" hidden>
    <p>Open the email link and enter this device code:</p>
    <strong id="code" style="font-size:2rem"></strong>
    <p>Waiting for confirmation…</p>
  </div>
<script>
const state = document.querySelector('#state');
const login = document.querySelector('#login');
const waiting = document.querySelector('#waiting');
async function json(path, options={}) {
  const response = await fetch(path, {
    ...options,
    headers: {'Content-Type':'application/json', ...(options.headers || {})}
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error);
  return body;
}
async function loadState() {
  const current = await json('/api/auth/state');
  if (current.logged_in) {
    state.innerHTML = `Signed in as <b>${current.email}</b>
      <button id="logout">Log out</button>`;
    document.querySelector('#logout').onclick = async () => {
      await json('/api/auth/logout', {method:'POST'});
      location.reload();
    };
  } else {
    state.textContent = 'Not signed in';
    login.hidden = false;
  }
}
login.onsubmit = async event => {
  event.preventDefault();
  try {
    const result = await json('/api/auth/request', {
      method:'POST',
      body:JSON.stringify({email:document.querySelector('#email').value})
    });
    login.hidden = true;
    waiting.hidden = false;
    document.querySelector('#code').textContent = result.user_code;
    const poller = setInterval(async () => {
      const status = await json('/api/auth/status');
      if (status.status === 'approved') {
        clearInterval(poller);
        location.reload();
      }
      if (status.status === 'expired') {
        clearInterval(poller);
        waiting.textContent = 'Login request expired. Reload and try again.';
      }
    }, 1500);
  } catch (error) { alert(error.message); }
};
loadState();
</script>
"""


@app.get("/api/me")
@auth.login_required
def me():
    return jsonify({"ok": True, "user": auth.current_user()})


@app.get("/api/admin")
@auth.admin_required
def admin():
    return jsonify({"ok": True, "message": "administrator access granted"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
