# AETHER MAIL

Почтовый сервер для собственного VPS. Мульти-языковой стек по спецификации PROJECT AETHER MAIL: **TypeScript/Next.js + Go + Rust + Java 21 + SQL + Bash + Lua**, один скрипт установки.

## Стек (спецификация §1)

| Язык | Компонент | Ответственность |
|------|-----------|-----------------|
| TypeScript + Next.js | `frontend/` | Веб-клиент: вход, дашборд, управление ящиками |
| Go | `services/api/` | Основной API: сессии, ящики, аудит-события с HMAC-подписью |
| Rust | `services/mime-worker/` | Безопасная обработка MIME: вложения, блокируемые расширения |
| Java 21 | `services/audit-worker/` | Фоновая агрегация статистики событий безопасности |
| SQL | `database/migrations/` | Схема PostgreSQL: аудит, аккаунты, сессии |
| Bash | `scripts/` | Установка, бэкапы (шифрованные), восстановление |
| Lua | `edge/nginx/` | Rate limiting на периметре (OpenResty) |

Плюс: docker-mailserver (Postfix/Dovecot/DKIM/DMARC/Fail2ban), OpenResty, certbot.

## Порты

| Порт | Назначение |
|------|-----------|
| 25 | Приём почты от других серверов |
| 465, 587 | Отправка (SMTPS / Submission) |
| 2525, 2526, 2527 | Альтернативные порты отправки |
| 80, 443 | `/` Next.js, `/api/` Go API, `/legacy/` старая панель |

## Структура

```
mailserver/
├── docker-compose.yml
├── frontend/               # Next.js (TypeScript)
├── services/
│   ├── api/                # Go API (аудит + ящики + сессии)
│   ├── mime-worker/        # Rust MIME-проверка вложений
│   └── audit-worker/       # Java 21 статистика событий
├── database/migrations/    # SQL (PostgreSQL)
├── scripts/                # Bash: install-mail.sh, backup.sh
├── edge/
│   ├── nginx/              # OpenResty + Lua rate-limit
│   └── panel/              # Python legacy panel (фолбэк на /legacy/)
└── docs/
```

## Установка на VPS

```bash
git clone https://github.com/SeVaYa139/mailserver.git
cd mailserver
sudo bash scripts/install-mail.sh
```

Скрипт спросит домен почты, поддомен панели и пароль администратора (пустой = сгенерирует). Требование: A-записи `mail.<домен>` и `<поддомен>.<домен>` на IP сервера до запуска. Подробности — [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

## Что работает

- Вход в панель (Next.js → Go API, PBKDF2 + подписанная cookie)
- Создание/удаление ящиков (Go API → docker-mailserver)
- Журнал событий безопасности: Go пишет в PostgreSQL с HMAC-подписью каждой записи, Java-воркер агрегирует статистику для дашборда
- Rate limiting на `/api/` (Lua/OpenResty): 30 запросов/30с на IP, на логин — 5
- Legacy Python-панель на `/legacy/` (отправка писем, DNS-справка) — шлёт события в Go-аудит
- Зашифрованные бэкапы: `bash scripts/backup.sh` / `--install-cron` / `--restore`
- CI: ShellCheck, Ruff, go vet/build, cargo check, javac, tsc + next build, Gitleaks, smoke-тесты

## Безопасность

См. [docs/SECURITY.md](docs/SECURITY.md) — модель угроз и честный список ограничений. Кратко: PBKDF2-хеши, HMAC-сессии, CSRF, Lua rate-limit, Fail2ban, ufw, секреты вне git, бэкапы AES-256.

## Управление

```bash
docker compose ps && docker compose logs -f api
docker exec mailserver setup email list
```

## Дорожная карта (остаток спецификации)

- [ ] Stalwart Mail Server (SMTP/IMAP/JMAP) вместо docker-mailserver
- [ ] Пользовательский вебмейл: входящие/папки/поиск через IMAP
- [ ] MFA (TOTP/WebAuthn), резервные коды, управление сессиями
- [ ] 7 языков интерфейса
- [ ] Интеграция mime-worker в пайплайн доставки почты
- [ ] Зашифрованные бэкапы PostgreSQL во внешнее хранилище

### Скриншоты legacy-панели

| Вход | Ящики | Отправка | DNS |
|------|-------|----------|-----|
| ![login](docs/screenshots/login.png) | ![mailboxes](docs/screenshots/mailboxes.png) | ![send](docs/screenshots/send.png) | ![dns](docs/screenshots/dns.png) |
