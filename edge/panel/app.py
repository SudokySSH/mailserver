"""Админ-панель AETHER MAIL: ящики, пароли, отправка писем, DNS-справка."""
import asyncio
import hashlib
import hmac
import os
import re
import smtplib
import subprocess
import time
from email.message import EmailMessage

import uvicorn
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

ADMIN_HASH = os.environ["PANEL_ADMIN_HASH"]  # формат: pbkdf2$salt_hex$hash_hex
SESSION_SECRET = os.environ.get("PANEL_SESSION_SECRET", ADMIN_HASH)
MAIL_DOMAIN = os.environ["MAIL_DOMAIN"]
PANEL_DOMAIN = os.environ["PANEL_DOMAIN"]
MAIL_HOST = os.environ.get("MAIL_HOST", "mailserver")
SECURE_COOKIE = os.environ.get("PANEL_SECURE_COOKIE", "true").lower() == "true"
COOKIE = "aether_session"
ITERATIONS = 200_000
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@" + re.escape(MAIL_DOMAIN) + r"$")
BRAND = "AETHER MAIL"

app = FastAPI(docs_url=None, redoc_url=None)


# ---------- крипто ----------

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, _ = stored.split("$")
        candidate = hash_password(password, bytes.fromhex(salt_hex))
        return hmac.compare_digest(candidate, stored)
    except (ValueError, AttributeError):
        return False


def _sign(data: bytes) -> str:
    return hmac.new(SESSION_SECRET.encode(), data, hashlib.sha256).hexdigest()


def session_token() -> str:
    return _sign(b"authenticated")


def csrf_token() -> str:
    return _sign(b"csrf-form")


def authed(request: Request) -> bool:
    return request.cookies.get(COOKIE) == session_token()


def require_auth(request: Request) -> None:
    if not authed(request):
        raise HTTPException(status_code=401)


def check_csrf(request: Request, token: str) -> None:
    if not token or not hmac.compare_digest(token, csrf_token()):
        raise HTTPException(status_code=403, detail="CSRF")


# ---------- docker-mailserver ----------

def run_setup(*args: str) -> tuple[bool, str]:
    cmd = ["docker", "exec", "mailserver", "setup", *args]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return False, "Команда не ответила за 60 секунд"
    except FileNotFoundError:
        return False, "docker недоступен внутри контейнера (соккет не смонтирован)"


def list_mailboxes() -> list[str]:
    ok, out = run_setup("email", "list")
    if not ok:
        return []
    boxes: list[str] = []
    for line in out.splitlines():
        m = re.search(r"([A-Za-z0-9._%+-]+@" + re.escape(MAIL_DOMAIN) + r")", line)
        if m and m.group(1) not in boxes:
            boxes.append(m.group(1))
    return sorted(boxes)


def dkim_record() -> str:
    """Устойчивый парсер bind-формата opendkim (склейка строк и кавычек)."""
    path = f"/mail-config/opendkim/keys/{MAIL_DOMAIN}/mail.txt"
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError:
        return ""
    body = re.sub(r"\([^)]*\)", "", raw)          # strip comments
    body = re.sub(r"\s+", "", body)               # glue split TXT chunks
    m = re.search(r"mail\._domainkeyIN TXT?\"(.*?)\"(?:$|\s)", body, re.IGNORECASE)
    if not m:
        return body[:400]
    return m.group(1).replace('""', '"')


# ---------- анти-брутфорс ----------

_attempts: dict[str, tuple[int, float]] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 60.0


def _prune_attempts(now: float) -> None:
    stale = [ip for ip, (n, t) in _attempts.items()
             if n < MAX_ATTEMPTS and now - t > LOCKOUT_SECONDS]
    for ip in stale:
        _attempts.pop(ip, None)


def _throttled(ip: str) -> bool:
    now = time.monotonic()
    _prune_attempts(now)
    count, first = _attempts.get(ip, (0, 0.0))
    return count >= MAX_ATTEMPTS and now - first < LOCKOUT_SECONDS


def _register_fail(ip: str) -> None:
    now = time.monotonic()
    count, first = _attempts.get(ip, (0, now))
    _attempts[ip] = (count + 1, first)


# ---------- рендер ----------

def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def page(request: Request, content: str, active: str = "") -> HTMLResponse:
    logged = authed(request)
    items = [("boxes", "/", "Ящики", "M20 4H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zm0 4-8 5-8-5V6l8 5 8-5v2z"),
             ("send", "/send-form", "Отправить письмо", "M2 21l21-9L2 3v7l15 2-15 2v7z"),
             ("dns", "/dns", "DNS-записи", "M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm7 9h-3a15 15 0 0 0-1.4-5.6A8 8 0 0 1 19 11zM12 4a13 13 0 0 1 2 7h-4a13 13 0 0 1 2-7zM5 11a8 8 0 0 1 4.4-5.6A15 15 0 0 0 8 11H5zm0 2h3a15 15 0 0 0 1.4 5.6A8 8 0 0 1 5 13zm7 7a13 13 0 0 1-2-7h4a13 13 0 0 1-2 7zm4.6-.4A15 15 0 0 0 16 13h3a8 8 0 0 1-2.4 6.6z")]
    nav = "".join(
        f'<a href="{href}" class="{ "on" if key == active else "" }">'
        f'<svg viewBox="0 0 24 24"><path d="{icon}"/></svg>{label}</a>'
        for key, href, label, icon in items
    ) if logged else ""
    logout = '<a href="/logout" class="logout"><svg viewBox="0 0 24 24"><path d="M17 7l-1.4 1.4L18.2 11H8v2h10.2l-2.6 2.6L17 17l5-5-5-5zM4 5h8V3H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h8v-2H4V5z"/></svg>Выйти</a>' if logged else ""
    html = f"""<!DOCTYPE html>
<html lang="ru"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{BRAND} · {esc(MAIL_DOMAIN)}</title>
<style>
* {{ box-sizing:border-box; margin:0; }}
:root {{
  --bg:#f6f8fc; --surface:#fff; --border:#e1e3e6; --text:#1f1f1f; --muted:#5f6368;
  --accent:#0b57d0; --accent-soft:#c2e7ff; --danger:#b3261e; --danger-soft:#f9dedc;
  --radius:12px; --shadow:0 1px 2px rgba(60,64,67,.3);
}}
body {{ font-family:"Google Sans",Roboto,"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--text); display:flex; min-height:100vh; }}
aside {{ width:260px; background:var(--surface); border-right:1px solid var(--border); padding:16px 12px; display:flex; flex-direction:column; gap:4px; position:sticky; top:0; height:100vh; }}
.logo {{ font-size:20px; font-weight:700; letter-spacing:.5px; padding:8px 12px 20px; }}
.logo span {{ color:var(--accent); }}
aside a {{ display:flex; align-items:center; gap:14px; padding:12px 16px; border-radius:0 24px 24px 0; color:var(--text); text-decoration:none; font-size:14px; margin-right:8px; }}
aside a:hover {{ background:#e9eef6; }}
aside a.on {{ background:var(--accent-soft); font-weight:600; }}
aside svg {{ width:20px; height:20px; fill:var(--muted); flex-shrink:0; }}
aside a.on svg {{ fill:var(--accent); }}
.logout {{ margin-top:auto; color:var(--muted); }}
main {{ flex:1; padding:28px 36px; max-width:980px; }}
h1 {{ font-size:22px; font-weight:500; margin-bottom:20px; }}
.card {{ background:var(--surface); border:1px solid var(--border); border-radius:var(--radius); padding:24px; margin-bottom:20px; box-shadow:var(--shadow); }}
h2 {{ font-size:15px; font-weight:600; margin-bottom:14px; }}
input, select, textarea {{ width:100%; padding:12px 14px; margin-bottom:12px; border:1px solid var(--border); border-radius:8px; font-size:14px; font-family:inherit; background:#fff; color:var(--text); transition:border-color .15s, box-shadow .15s; }}
input:focus, select:focus, textarea:focus {{ outline:none; border-color:var(--accent); box-shadow:0 0 0 2px rgba(11,87,208,.2); }}
button {{ background:var(--accent); color:#fff; border:0; padding:11px 22px; border-radius:20px; font-size:14px; font-weight:500; cursor:pointer; transition:box-shadow .15s; }}
button:hover {{ box-shadow:0 2px 6px rgba(11,87,208,.4); }}
button.danger {{ background:var(--danger); }}
.msg {{ padding:13px 16px; border-radius:8px; margin-bottom:18px; font-size:14px; }}
.msg.ok {{ background:#e6f4ea; color:#137333; border:1px solid #ceead6; }}
.msg.err {{ background:var(--danger-soft); color:var(--danger); border:1px solid #f1c1bd; }}
table {{ width:100%; border-collapse:collapse; font-size:14px; }}
th {{ text-align:left; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.8px; padding:10px 8px; border-bottom:1px solid var(--border); }}
td {{ padding:12px 8px; border-bottom:1px solid #f0f1f3; vertical-align:middle; }}
tr:hover td {{ background:#f8fafd; }}
form.inline {{ display:inline-flex; gap:8px; align-items:center; margin:0; }}
form.inline input {{ width:170px; margin:0; padding:8px 10px; }}
form.inline button {{ padding:8px 16px; border-radius:16px; }}
code, pre {{ background:#f0f4f9; border:1px solid var(--border); border-radius:6px; padding:2px 6px; font-size:13px; font-family:Consolas,monospace; }}
pre {{ padding:16px; overflow-x:auto; white-space:pre-wrap; word-break:break-all; line-height:1.6; }}
.grid {{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }}
.search {{ max-width:420px; }}
.empty {{ color:var(--muted); text-align:center; padding:24px 0; }}
a.back {{ color:var(--accent); text-decoration:none; font-size:14px; }}
@media (max-width:760px) {{
  aside {{ width:64px; padding:12px 6px; }} aside a span {{ display:none; }}
  aside a {{ justify-content:center; padding:12px; }} .logo {{ font-size:0; padding-bottom:12px; }}
  .logo::after {{ content:"A"; font-size:22px; color:var(--accent); }} main {{ padding:16px; }}
  .grid {{ grid-template-columns:1fr; }}
}}
</style></head><body>
<aside><div class="logo">AETHER <span>MAIL</span></div>{nav}{logout}</aside>
<main>{content}</main></body></html>"""
    return HTMLResponse(html)


# ---------- маршруты ----------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if not authed(request):
        return RedirectResponse("/login")
    token = csrf_token()
    boxes = list_mailboxes()
    rows = "".join(
        f'<tr data-name="{esc(m.lower())}"><td style="font-weight:500">{esc(m)}</td><td>'
        f'<form class="inline" method="post" action="/mailbox/password">'
        f'<input type="hidden" name="csrf" value="{token}">'
        f'<input type="hidden" name="email" value="{esc(m)}">'
        f'<input type="password" name="password" placeholder="Новый пароль" required minlength="8">'
        f'<button type="submit">Сменить</button></form>'
        f'<form class="inline" method="post" action="/mailbox/delete" onsubmit="return confirm(\'Удалить ящик {esc(m)}?\')">'
        f'<input type="hidden" name="csrf" value="{token}">'
        f'<input type="hidden" name="email" value="{esc(m)}">'
        f'<button type="submit" class="danger">Удалить</button></form></td></tr>'
        for m in boxes
    ) or '<tr><td colspan="2" class="empty">Ящиков пока нет</td></tr>'
    body = f"""
<h1>Ящики @{esc(MAIL_DOMAIN)}</h1>
<div class="card"><h2>Создать ящик</h2>
<form method="post" action="/mailbox/create">
<input type="hidden" name="csrf" value="{token}">
<div class="grid">
<input name="local" placeholder="Имя ящика (например: info)" required autocomplete="off">
<input type="password" name="password" placeholder="Пароль (минимум 8 символов)" required minlength="8">
</div>
<button type="submit">Создать ящик</button></form></div>
<div class="card"><h2>Существующие ящики</h2>
<input class="search" id="q" type="search" placeholder="Поиск по ящикам…" oninput="filterRows()">
<table id="boxes"><tr><th>Адрес</th><th>Действия</th></tr>{rows}</table></div>
<script>
function filterRows() {{
  const q = document.getElementById('q').value.toLowerCase();
  document.querySelectorAll('#boxes tr[data-name]').forEach(tr => {{
    tr.style.display = tr.dataset.name.includes(q) ? '' : 'none';
  }});
}}
</script>"""
    return page(request, body, "boxes")


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    if authed(request):
        return RedirectResponse("/")
    body = """
<h1>Вход в панель</h1>
<div class="card" style="max-width:400px">
<form method="post" action="/login">
<input type="password" name="password" placeholder="Пароль администратора" required autofocus>
<button type="submit" style="width:100%">Войти</button></form></div>"""
    return page(request, body)


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    ip = request.client.host if request.client else "unknown"
    if _throttled(ip):
        return page(request, '<div class="msg err">Слишком много попыток. Подожди минуту и попробуй снова.</div>'
                              '<p><a class="back" href="/login">← Назад ко входу</a></p>')
    if check_password(password, ADMIN_HASH):
        _attempts.pop(ip, None)
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(COOKIE, session_token(), httponly=True, samesite="lax", secure=SECURE_COOKIE)
        return resp
    _register_fail(ip)
    await asyncio.sleep(0.7)  # замедляем перебор, не блокируя event loop
    return RedirectResponse("/login", status_code=303)


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie(COOKIE)
    return resp


@app.post("/mailbox/create")
async def mailbox_create(request: Request, csrf: str = Form(...), local: str = Form(...), password: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf)
    local = local.strip().lower()
    email = f"{local}@{MAIL_DOMAIN}"
    if not re.fullmatch(r"[a-z0-9._%+-]{1,64}", local):
        return page(request, '<div class="msg err">Некорректное имя ящика: только латиница, цифры и . _ % + -</div>'
                              '<p><a class="back" href="/">← Назад</a></p>')
    if len(password) < 8:
        return page(request, '<div class="msg err">Пароль должен быть минимум 8 символов.</div>'
                              '<p><a class="back" href="/">← Назад</a></p>')
    ok, out = run_setup("email", "add", email, password)
    body = (f'<div class="msg ok">Ящик <b>{esc(email)}</b> создан. Пароль: <code>{esc(password)}</code> — '
            f'передай его владельцу и сохрани в надёжном месте.</div>'
            if ok else f'<div class="msg err">Ошибка: {esc(out)}</div>')
    return page(request, body + '<p><a class="back" href="/">← К списку ящиков</a></p>')


@app.post("/mailbox/password")
async def mailbox_password(request: Request, csrf: str = Form(...), email: str = Form(...), password: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf)
    if not EMAIL_RE.fullmatch(email) or len(password) < 8:
        return page(request, '<div class="msg err">Некорректные данные: пароль минимум 8 символов.</div>'
                              '<p><a class="back" href="/">← Назад</a></p>')
    ok, out = run_setup("email", "update", email, password)
    if not ok and ("unknown" in out.lower() or "not found" in out.lower() or "does not exist" in out.lower()):
        ok, out = run_setup("email", "add", email, password)
    if ok:
        body = (f'<div class="msg ok">Пароль ящика <b>{esc(email)}</b> изменён: '
                f'<code>{esc(password)}</code></div>')
    else:
        body = f'<div class="msg err">Ошибка: {esc(out)}</div>'
    return page(request, body + '<p><a class="back" href="/">← К списку ящиков</a></p>')


@app.post("/mailbox/delete")
async def mailbox_delete(request: Request, csrf: str = Form(...), email: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf)
    if not EMAIL_RE.fullmatch(email):
        return page(request, '<div class="msg err">Некорректный адрес.</div><p><a class="back" href="/">← Назад</a></p>')
    ok, out = run_setup("email", "del", email)
    if not ok and "usage" in out.lower():
        ok, out = run_setup("email", "delete", email)
    body = (f'<div class="msg ok">Ящик <b>{esc(email)}</b> удалён.</div>'
            if ok else f'<div class="msg err">Ошибка: {esc(out)}</div>')
    return page(request, body + '<p><a class="back" href="/">← К списку ящиков</a></p>')


@app.get("/send-form", response_class=HTMLResponse)
async def send_form(request: Request):
    if not authed(request):
        return RedirectResponse("/login")
    token = csrf_token()
    boxes = list_mailboxes()
    if not boxes:
        return page(request, '<div class="msg err">Сначала создай хотя бы один ящик.</div>'
                             '<p><a class="back" href="/">← К ящикам</a></p>', "send")
    options = "".join(f'<option value="{esc(m)}">{esc(m)}</option>' for m in boxes)
    body = f"""
<h1>Новое письмо</h1>
<div class="card"><form method="post" action="/send">
<input type="hidden" name="csrf" value="{token}">
<label>От кого</label><select name="from_email">{options}</select>
<label>Пароль этого ящика</label><input type="password" name="password" required>
<label>Кому</label><input type="email" name="to" placeholder="recipient@example.com" required>
<label>Тема</label><input name="subject" required>
<label>Текст</label><textarea name="body" rows="9" required></textarea>
<button type="submit">Отправить</button></form></div>"""
    return page(request, body, "send")


@app.post("/send")
async def send(request: Request, csrf: str = Form(...), from_email: str = Form(...), password: str = Form(...),
               to: str = Form(...), subject: str = Form(...), body: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf)
    if not EMAIL_RE.fullmatch(from_email):
        return page(request, '<div class="msg err">Некорректный адрес отправителя.</div>'
                              '<p><a class="back" href="/send-form">← Назад</a></p>')
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
    return page(request, result + '<p><a class="back" href="/send-form">← Отправить ещё одно</a></p>', "send")


@app.get("/dns", response_class=HTMLResponse)
async def dns(request: Request):
    if not authed(request):
        return RedirectResponse("/login")
    dkim = dkim_record() or "DKIM ещё не сгенерирован — выполни на сервере: docker exec mailserver setup config dkim"
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
    return page(request, body, "dns")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
