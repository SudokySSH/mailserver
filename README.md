# Mail Server + Admin Panel

Почтовый сервер на VPS с веб-панелью управления. Один скрипт — готовая почта.

## Что ставится

- **docker-mailserver** — SMTP-сервер (Postfix + Dovecot + OpenDKIM + OpenDMARC + Fail2ban)
- **Панель управления** (Python/FastAPI) — ящики, пароли, отправка писем, DNS-справка
- **nginx** — HTTPS-прокси для панели
- **certbot** — SSL-сертификаты Let's Encrypt + автообновление

## Порты

| Порт | Назначение |
|------|-----------|
| 25 | Приём почты от других серверов (нельзя закрывать) |
| 465 | Отправка (SMTPS, SSL) |
| 587 | Отправка (Submission, STARTTLS) |
| 2525, 2526, 2527 | Альтернативные порты отправки (проброс на 587) |
| 80, 443 | Панель управления (HTTP → редирект на HTTPS) |

## Установка на VPS

```bash
# скопировать папку mailserver на сервер, затем:
cd mailserver
sudo bash install-mail.sh
```

Скрипт спросит:
1. **Домен почты** — например `example.com` (ящики будут `имя@example.com`)
2. **Поддомен панели** — например `panel` → панель будет на `https://panel.example.com`
3. **Пароль администратора** — если оставить пустым, сгенерируется случайный

**Перед запуском** убедись, что DNS A-записи `mail.<домен>` и `<поддомен>.<домен>` указывают на IP сервера — иначе certbot не получит SSL.

После установки скрипт выведет DNS-записи, которые нужно добавить (MX, SPF, DMARC, DKIM) — они также доступны в панели на странице `/dns`.

## Панель управления

`https://<поддомен>.<домен>` — вход по паролю администратора:

- **Ящики** — создание ящика с паролем, смена пароля, удаление
- **Отправить письмо** — отправка от любого созданного ящика через SMTP с авторизацией
- **DNS-записи** — все записи для корректной доставки, включая публичный ключ DKIM

### Скриншоты

| Вход | Ящики |
|------|-------|
| ![login](docs/screenshots/login.png) | ![mailboxes](docs/screenshots/mailboxes.png) |

| Отправка | DNS-записи |
|----------|-----------|
| ![send](docs/screenshots/send.png) | ![dns](docs/screenshots/dns.png) |

## Безопасность

- Пароль администратора хранится в панели только как PBKDF2-хеш (200 000 итераций)
- `.env.mail` и `.env.panel` не публиковать, в них пароли и хеш
- Session-cookie: HttpOnly + SameSite
- Fail2ban защищает SMTP от брутфорса
- Порт панели наружу закрыт — доступ только через nginx (443)

## Управление

```bash
docker compose ps                # статус
docker compose logs -f mailserver
docker exec mailserver setup email list   # список ящиков из консоли
docker exec mailserver setup email add user@example.com 'пароль'
docker exec mailserver setup config dkim  # пересоздать DKIM
```
