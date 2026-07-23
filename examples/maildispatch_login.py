#!/usr/bin/env python3
"""Use maglink with a MailDispatch API key.

Required MailDispatch API-key scopes:
    mail:send
    mail:authentication

Run:
    pip install "maglink[flask]"
    export SECRET_KEY="..."
    export MAILDISPATCH_API_KEY="md_live_..."
    export MAILDISPATCH_API_URL="https://mail.example.com/api/v1/messages"
    export BASE_URL="https://app.example.com"
    export ALLOWED_EMAILS="alice@example.com,bob@example.com"
    flask --app examples/maildispatch_login.py run
"""

from __future__ import annotations

import os
from pathlib import Path

from flask import Flask, jsonify
from maglink import AuthCore, HttpMailer, SqliteStore
from maglink.flask import EmailAuth

BASE_URL = os.environ["BASE_URL"].rstrip("/")
DATA_DIR = Path(os.getenv("DATA_DIR", "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

allowed_emails = [
    value.strip().lower()
    for value in os.environ["ALLOWED_EMAILS"].split(",")
    if value.strip()
]
admin_emails = [
    value.strip().lower()
    for value in os.getenv("ADMIN_EMAILS", "").split(",")
    if value.strip()
]

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=BASE_URL.startswith("https://"),
)

mailer = HttpMailer(
    endpoint=os.environ["MAILDISPATCH_API_URL"],
    api_key=os.environ["MAILDISPATCH_API_KEY"],
    sender_id=os.getenv("MAILDISPATCH_SENDER_ID", "system"),
    timeout=10,
)
core = AuthCore(
    store=SqliteStore(str(DATA_DIR / "maglink.db")),
    mailer=mailer,
    verify_url_base=f"{BASE_URL}/api/auth/verify",
    allowed_emails=allowed_emails,
    admin_emails=admin_emails,
    login_sender_id=os.getenv("MAILDISPATCH_SENDER_ID", "system"),
    code_ttl=900,
    rate_max=5,
    rate_window=900,
)
auth = EmailAuth(core, require_captcha=True)
app.register_blueprint(auth.blueprint(url_prefix="/api/auth"))


@app.get("/")
def index():
    return """<!doctype html><meta charset="utf-8"><title>Email login</title>
<body style="font:16px system-ui;max-width:36rem;margin:3rem auto">
<h1>Email login</h1><div id="root">Loading…</div>
<script>
const root = document.querySelector('#root');
async function api(path, options={}) {
  const response = await fetch(path, {...options,
    headers:{'Content-Type':'application/json', ...(options.headers || {})}});
  const body = await response.json();
  if (!response.ok) throw new Error(body.message || body.error);
  return body;
}
async function captcha() {
  const result = await api('/api/auth/captcha');
  document.querySelector('#captcha').src = result.image;
}
async function start() {
  const state = await api('/api/auth/state');
  if (state.logged_in) {
    root.innerHTML = `<p>Signed in as <b>${state.email}</b></p>
      <button id="logout">Log out</button>`;
    document.querySelector('#logout').onclick = async () => {
      await api('/api/auth/logout', {method:'POST'}); location.reload();
    };
    return;
  }
  root.innerHTML = `<form id="form">
    <p><input id="email" type="email" placeholder="alice@example.com" required></p>
    <p><img id="captcha" alt="captcha"><br><input id="answer" required></p>
    <button>Send login email</button></form><div id="message"></div>`;
  await captcha();
  document.querySelector('#form').onsubmit = async event => {
    event.preventDefault();
    try {
      const result = await api('/api/auth/request', {method:'POST', body:JSON.stringify({
        email:document.querySelector('#email').value,
        captcha:document.querySelector('#answer').value
      })});
      document.querySelector('#form').hidden = true;
      document.querySelector('#message').innerHTML =
        `<p>Open the email and enter this code:</p><h2>${result.user_code}</h2>
         <p>Waiting for confirmation…</p>`;
      const poller = setInterval(async () => {
        const status = await api('/api/auth/status');
        if (status.status === 'approved') { clearInterval(poller); location.reload(); }
        if (status.status === 'expired') {
          clearInterval(poller); document.querySelector('#message').textContent='Expired';
        }
      }, 1500);
    } catch (error) { alert(error.message); await captcha(); }
  };
}
start().catch(error => { root.textContent = error.message; });
</script>"""


@app.get("/api/me")
@auth.login_required
def me():
    return jsonify({"ok": True, "user": auth.current_user()})
