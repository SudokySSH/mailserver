# Деплой AETHER MAIL

## Требования

- VPS с Ubuntu 22.04/24.04, минимум 1 ГБ RAM (2 ГБ комфортно), 10 ГБ диска.
- Домен, делегированный на твои NS, с доступом к редактированию DNS.
- Открытые порты на хостинге/VPS-панели: 25, 80, 443 (465/587/2525–2527 — если файрвол внешний).

## Шаг 1 — DNS до установки

Обязательно **до** запуска скрипта:

```
A    mail.example.com        → IP сервера
A    panel.example.com       → IP сервера
```

(`example.com` — твой домен, `panel` — выбранный поддомен панели.)

## Шаг 2 — установка

```bash
git clone https://github.com/SevaYa139/mailserver.git
cd mailserver
sudo bash scripts/install-mail.sh
```

Скрипт: ставит Docker и certbot, настраивает ufw, получает SSL, поднимает контейнеры, генерирует DKIM, создаёт `admin@<домен>`. В конце печатает пароль панели и оставшиеся DNS-записи — **сохрани вывод**.

Повторный запуск на том же сервере: `sudo bash scripts/install-mail.sh --reinstall` (перезапишет `.env.mail`/`.env.panel`).

## Шаг 3 — DNS после установки

Добавь записи из вывода скрипта (дублируются в панели на `/dns`):

```
MX   example.com             10 mail.example.com
TXT  example.com             v=spf1 mx -all
TXT  _dmarc.example.com      v=DMARC1; p=quarantine; rua=mailto:admin@example.com
TXT  mail._domainkey...      <публичный ключ DKIM из панели>
```

Проверка после пропагации:

```bash
dig MX example.com +short
dig TXT mail._domainkey.example.com +short
# тест отправки с сервера:
swaks --from admin@example.com --to твой@gmail.com --server localhost
```

## Обновление

```bash
cd mailserver
git pull
docker compose pull          # новые образы
docker compose up -d --build # пересборка панели
docker image prune -f
```

Откат: `git checkout <прошлый коммит>` → те же команды. Конфиги и письма в `data/`, `config/`, `certs/` — не трогаются git-ом.

## Бэкапы

```bash
sudo bash scripts/backup.sh                 # один раз
sudo bash scripts/backup.sh --install-cron  # ежедневно в 03:47 + еженедельная проверка восстановления
```

Бэкап: tar-архив `./config`, `./certs`, `./data/mail-state` + список ящиков, зашифрованный AES-256 (openssl), в `./backups`. Ключ — в `BACKUP_PASSPHRASE_FILE` (по умолчанию `/root/.config/aether-backup.key`; храни его отдельно от архивов). Восстановление на чистом сервере: `sudo bash scripts/backup.sh --restore backups/<файл>.tar.gz.age`.
