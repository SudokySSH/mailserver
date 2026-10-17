"""Админ-панель почтового сервера: ящики, пароли, отправка писем, DNS-справка."""
import hashlib
import hmac
import os
import re
import smtplib
import subprocess
import time
from email.message import EmailMessage

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
import uvicorn

ADMIN_HASH = os.environ["PANEL_ADMIN_HASH"]  # формат: pbkdf2$salt_hex$hash_hex
SESSION_SECRET = os.environ.get("PANEL_SESSION_SECRET", ADMIN_HASH)
MAIL_DOMAIN = os.environ["MAIL_DOMAIN"]
PANEL_DOMAIN = os.environ["PANEL_DOMAIN"]
MAIL_HOST = os.environ.get("MAIL_HOST", "mailserver")
COOKIE = "mailpanel_session"
ITERATIONS = 200_000
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@" + re.escape(MAIL_DOMAIN) + r"$")

app = FastAPI(docs_url=None, redoc_url=None)


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, hash_hex = stored.split("$")
        candidate = hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate, stored)
    except (ValueError, AttributeError):
        return False


def session_token() -> str:
    return hmac.new(SESSION_SECRET.encode(), b"authenticated", hashlib.sha256).hexdigest()


def authed(request: Request) -> bool:
    return request.cookies.get(COOKIE) == session_token()


def run_setup(*args: str) -> tuple[bool, str]:
    """Выполнить команду управления docker-mailserver."""
    cmd = ["docker", "exec", "mailserver", "setup", *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = (r.stdout + r.stderr).strip()
        return r.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, "Команда не ответила за 60 секунд"
    except FileNotFoundError:
        return False, "docker недоступен внутри контейнера (соккет не смонтирован)"


def list_mailboxes() -> list[str]:
    ok, out = run_setup("email", "list")
    if not ok:
        return []
    boxes = []
    for line in out.splitlines():
        m = re.search(r"([A-Za-z0-9._%+-]+@" + re.escape(MAIL_DOMAIN) + r")", line)
        if m and m.group(1) not in boxes:
            boxes.append(m.group(1))
    return sorted(boxes)


def dkim_record() -> str:
    path = f"/mail-config/opendkim/keys/{MAIL_DOMAIN}/mail.txt"
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
        content = re.sub(r"\s*\n\s*", "", content)
        m = re.search(r"mail\._domainkey[^\"]*\"(v=DKIM1[^\"]*)\"", content)
        if m:
            value = m.group(1).replace('" "', "").replace('"', "")
            return f"v=DKIM1; {value.split(';', 1)[1].strip()}" if value.lower().startswith("v=dkim1;") else value
        return content
    except OSError:
        return ""


def esc(s: str) -> str:
    return (
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def page(request: Request, body: str) -> HTMLResponse:
    logged = authed(request)
    nav = (
        f'<nav><a href="/">Ящики</a><a href="/send-form">Отправить письмо</a>'
        f'<a href="/dns">DNS-записи</a><a href="/logout" class="right">Выйти</a></nav>'
        if logged
        else ""
    )
    html = f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Почта {esc(MAIL_DOMAIN)}</title>
<style>
:root {{ --bg:#0f1117; --card:#1a1d27; --border:#2a2e3f; --text:#e6e8f0; --muted:#8b90a5; --accent:#5b8cff; --ok:#3ecf8e; --err:#ff6b6b; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; font-family:Segoe UI,system-ui,sans-serif; background:var(--bg); color:var(--text); }}
nav {{ display:flex; gap:4px; background:var(--card); border-bottom:1px solid var(--border); padding:10px 20px; }}
nav a {{ color:var(--muted); text-decoration:none; padding:8px 14px; border-radius:8px; font-size:14px; }}
nav a:hover {{ color:var(--text); background:#22263a; }}
nav a.right {{ margin-left:auto; }}
main {{ max-width:860px; margin:32px auto; padding:0 16px; }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:22px; margin-bottom:18px; }}
h1 {{ font-size:22px; margin:0 0 18px; }} h2 {{ font-size:16px; margin:0 0 14px; color:var(--muted); font-weight:600; }}
input, textarea {{ width:100%; padding:10px 12px; margin-bottom:10px; background:#12141d; border:1px solid var(--border); border-radius:8px; color:var(--text); font-size:14px; }}
button {{ background:var(--accent); color:#fff; border:0; padding:10px 18px; border-radius:8px; font-size:14px; cursor:pointer; }}
button:hover {{ filter:brightness(1.1); }}
button.danger {{ background:var(--err); }}
.msg {{ padding:12px 14px; border-radius:8px; margin-bottom:16px; font-size:14px; }}
.msg.ok {{ background:#123524; color:var(--ok); border:1px solid #1f5c3f; }}
.msg.err {{ background:#3a1a1a; color:var(--err); border:1px solid #5c2a2a; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
td, th {{ padding:10px 8px; border-bottom:1px solid var(--border); text-align:left; }}
th {{ color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; }}
form.inline {{ display:inline; }}
code, pre {{ background:#12141d; border:1px solid var(--border); border-radius:6px; padding:2px 6px; font-size:13px; }}
pre {{ padding:12px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
@media (max-width:640px) {{ .grid {{ grid-template-columns:1fr; }} }}
</style></head><body>{nav}<main>{body}</main></body></html>"""
    return HTMLResponse(html)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not authed(request):
        return RedirectResponse("/login")
    boxes = list_mailboxes()
    rows = "".join(
        f"<tr><td>{esc(m)}</td><td>"
        f'<form class="inline" method="post" action="/mailbox/password" onsubmit="return confirm(\'Сменить пароль?\')">'
        f'<input type="hidden" name="email" value="{esc(m)}"><input type="password" name="password" placeholder="Новый пароль" required style="width:180px;display:inline-block">'
        f'<button type="submit">Сменить</button></form> '
        f'<form class="inline" method="post" action="/mailbox/delete" onsubmit="return confirm(\'Удалить ящик {esc(m)}?\')">'
        f'<input type="hidden" name="email" value="{esc(m)}"><button type="submit" class="danger">Удалить</button></form>'
        f"</td></tr>"
        for m in boxes
    ) or '<tr><td colspan="2" style="color:var(--muted)">Ящиков пока нет</td></tr>'
    body = f"""
<h1>Почтовые ящики</h1>
<div class="card"><h2>Создать ящик</h2>
<form method="post" action="/mailbox/create">
<div class="grid">
<input name="local" placeholder="имя (например: info)" required>
<input type="password" name="password" placeholder="Пароль" required minlength="8">
</div>
<button type="submit">Создать ящик @{esc(MAIL_DOMAIN)}</button></form></div>
<div class="card"><h2>Существующие ящики</h2>
<table><tr><th>Адрес</th><th>Действия</th></tr>{rows}</table></div>"""
    return page(request, body)


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    body = """
<h1>Вход в панель</h1>
<div class="card" style="max-width:400px">
<form method="post" action="/login">
<input type="password" name="password" placeholder="Пароль администратора" required autofocus>
<button type="submit" style="width:100%">Войти</button></form></div>"""
    return page(request, body)


_login_attempts: dict[str, tuple[int, float]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60.0


def _throttled(ip: str) -> bool:
    count, first = _login_attempts.get(ip, (0, 0.0))
    if count >= MAX_ATTEMPTS and time.monotonic() - first < LOCKOUT_SECONDS:
        return True
    if time.monotonic() - first >= LOCKOUT_SECONDS:
        _login_attempts.pop(ip, None)
    return False


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"
    if _throttled(ip):
        return page(request, '<div class="msg err">Слишком много попыток. Подожди минуту.</div>'
                              '<p><a href="/login">← Назад</a></p>')
    if check_password(password, ADMIN_HASH):
        _login_attempts.pop(ip, None)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, session_token(), httponly=True, samesite="lax")
        return resp
    count, first = _login_attempts.get(ip, (0, time.monotonic()))
    _login_attempts[ip] = (count + 1, first)
    time.sleep(0.7)  # замедляем перебор
    resp = RedirectResponse("/login", status_code=303)
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


@app.post("/mailbox/create")
async def mailbox_create(request: Request, local: str = Form(...), password: str = Form(...)):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    local = local.strip().lower()
    email = f"{local}@{MAIL_DOMAIN}"
    if not re.fullmatch(r"[a-z0-9._%+-]{1,64}", local) or not EMAIL_RE.fullmatch(email):
        return page(request, f'<div class="msg err">Некорректное имя ящика.</div><p><a href="/">← Назад</a></p>')
    if len(password) < 8:
        return page(request, '<div class="msg err">Пароль минимум 8 символов.</div><p><a href="/">← Назад</a></p>')
    ok, out = run_setup("email", "add", email, password)
    if ok:
        body = (f'<div class="msg ok">Ящик <b>{esc(email)}</b> создан. Пароль: '
                f'<code>{esc(password)}</code> — передай его владельцу и сохрани в надёжном месте.</div>'
                f'<p><a href="/">← К списку ящиков</a></p>')
    else:
        body = f'<div class="msg err">Ошибка: {esc(out)}</div><p><a href="/">← Назад</a></p>'
    return page(request, body)


@app.post("/mailbox/password")
async def mailbox_password(request: Request, email: str = Form(...), password: str = Form(...)):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    if not EMAIL_RE.fullmatch(email) or len(password) < 8:
        return page(request, '<div class="msg err">Некорректные данные (пароль минимум 8 символов).</div><p><a href="/">← Назад</a></p>')
    ok, out = run_setup("email", "update", email, password)
    if not ok and "update" in out.lower() or not ok and "unknown" in out.lower():
        ok, out = run_setup("email", "add", email, password)  # резервный вариант для старых версий
    if ok:
        body = (f'<div class="msg ok">Пароль ящика <b>{esc(email)}</b> изменён: '
                f'<code>{esc(password)}</code></div><p><a href="/">← К списку ящиков</a></p>')
    else:
        body = f'<div class="msg err">Ошибка: {esc(out)}</div><p><a href="/">← Назад</a></p>'
    return page(request, body)


@app.post("/mailbox/delete")
async def mailbox_delete(request: Request, email: str = Form(...)):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    if not EMAIL_RE.fullmatch(email):
        return page(request, '<div class="msg err">Некорректный адрес.</div><p><a href="/">← Назад</a></p>')
    ok, out = run_setup("email", "del", email)
    if not ok and "usage" in out.lower():
        ok, out = run_setup("email", "delete", email)
    body = (
        f'<div class="msg ok">Ящик <b>{esc(email)}</b> удалён.</div>'
        if ok else f'<div class="msg err">Ошибка: {esc(out)}</div>'
    ) + '<p><a href="/">← К списку ящиков</a></p>'
    return page(request, body)


@app.get("/send-form", response_class=HTMLResponse)
async def send_form(request: Request):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    boxes = list_mailboxes()
    options = "".join(f'<option value="{esc(m)}">{esc(m)}</option>' for m in boxes)
    body = f"""
<h1>Отправка письма</h1>
<div class="card"><form method="post" action="/send">
<label>От кого</label><select name="from_email">{options}</select>
<label>Пароль этого ящика</label><input type="password" name="password" required>
<label>Кому</label><input type="email" name="to" placeholder="recipient@example.com" required>
<label>Тема</label><input name="subject" required>
<label>Текст</label><textarea name="body" rows="8" required></textarea>
<button type="submit">Отправить</button></form></div>"""
    return page(request, body)


@app.post("/send")
async def send(request: Request, from_email: str = Form(...), password: str = Form(...),
               to: str = Form(...), subject: str = Form(...), body: str = Form(...)):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    if not EMAIL_RE.fullmatch(from_email):
        return page(request, '<div class="msg err">Некорректный адрес отправителя.</div><p><a href="/send-form">← Назад</a></p>')
    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(MAIL_HOST, 587, timeout=30) as smtp:
            smtp.starttls()
            smtp.login(from_email, password)
            smtp.send_message(msg)
        result = '<div class="msg ok">Письмо отправлено.</div>'
    except smtplib.SMTPException as e:
        result = f'<div class="msg err">Ошибка SMTP: {esc(str(e))}</div>'
    except OSError as e:
        result = f'<div class="msg err">Сетевая ошибка: {esc(str(e))}</div>'
    return page(request, result + '<p><a href="/send-form">← Отправить ещё</a></p>')


@app.get("/dns", response_class=HTMLResponse)
async def dns(request: Request):
    if not authed(request):
        return RedirectResponse("/login", status_code=303)
    dkim = dkim_record() or "DKIM ещё не сгенерирован — запусти на сервере: docker exec mailserver setup config dkim"
    body = f"""
<h1>DNS-записи для {esc(MAIL_DOMAIN)}</h1>
<div class="card"><pre>Тип   Имя                    Значение
A     mail                   &lt;IP твоего VPS&gt;
MX    {esc(MAIL_DOMAIN):22} 10 mail.{esc(MAIL_DOMAIN)}
TXT   {esc(MAIL_DOMAIN):22} v=spf1 mx -all
TXT   mail                   v=spf1 a -all
TXT   _dmarc                 v=DMARC1; p=quarantine; rua=mailto:admin@{esc(MAIL_DOMAIN)}
TXT   mail._domainkey        {esc(dkim)}</pre></div>
<div class="card"><h2>Порты сервера</h2>
<pre>25   — приём почты от других серверов (обязателен)
465  — отправка (SMTPS, SSL)
587  — отправка (Submission, STARTTLS)
2525, 2526, 2527 — альтернативные порты отправки</pre></div>"""
    return page(request, body)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
