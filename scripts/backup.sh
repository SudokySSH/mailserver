#!/usr/bin/env bash
# backup.sh — зашифрованные бэкапы AETHER MAIL + проверка восстановления.
#
# Использование:
#   bash scripts/backup.sh                    # создать бэкап в ./backups
#   bash scripts/backup.sh --restore <файл>   # восстановить на ЧИСТОМ сервере после install-mail.sh
#   bash scripts/backup.sh --install-cron     # ежедневный бэкап + еженедельная проверка восстановления
#
# Шифрование: AES-256-CBC + PBKDF2 (openssl). Ключ-фраза хранится в
# BACKUP_PASSPHRASE_FILE (по умолчанию /root/.config/aether-backup.key).
# Храни этот файл ОТДЕЛЬНО от архивов бэкапов.
set -euo pipefail

cd "$(dirname "$0")/.."
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="./backups"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass_file() {
  echo "${BACKUP_PASSPHRASE_FILE:-/root/.config/aether-backup.key}"
}

ensure_key() {
  local f
  f=$(pass_file)
  if [ ! -f "$f" ]; then
    mkdir -p "$(dirname "$f")"
    (umask 077; openssl rand -base64 48 | tr -d '\n' > "$f")
    echo "Сгенерирован ключ шифрования бэкапов: $f"
    echo "СКОПИРУЙ ЕГО В БЕЗОПАСНОЕ МЕСТО — без ключа бэкапы не восстановить."
  fi
}

create_backup() {
  mkdir -p "$BACKUP_DIR"
  ensure_key
  local out="${BACKUP_DIR}/aether-${STAMP}.tar.gz.age"

  echo "=== Создание бэкапа ${out} ==="
  mkdir -p "$TMP/aether"
  for d in config certs data/mail data/mail-state; do
    [ -e "$d" ] && cp -a "$d" "$TMP/aether/"
  done
  # Дамп PostgreSQL (аудит, аккаунты, сессии)
  if docker exec aether-db pg_dump -U aether -d aether --no-owner > "$TMP/aether/postgres.sql" 2>/dev/null; then
    echo "postgres dump: ok ($(wc -l < "$TMP/aether/postgres.sql") строк)"
  else
    echo "postgres dump: пропущен (БД недоступна)"
  fi
  docker exec mailserver setup email list > "$TMP/aether/mailboxes.txt" 2>/dev/null \
    || echo "(список ящиков недоступен — контейнер остановлен)" > "$TMP/aether/mailboxes.txt"

  tar -czf "$TMP/aether.tar.gz" -C "$TMP" aether
  openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt \
    -pass file:"$(pass_file)" \
    -in "$TMP/aether.tar.gz" -out "$out"
  local sha
  sha=$(sha256sum "$out" | cut -d' ' -f1)
  echo "$sha  $(basename "$out")" > "${out}.sha256"

  # ротация: оставляем 14 последних
  ls -1t "$BACKUP_DIR"/aether-*.tar.gz.age 2>/dev/null | tail -n +15 | xargs -r rm -f
  ls -1t "$BACKUP_DIR"/aether-*.sha256 2>/dev/null | tail -n +15 | xargs -r rm -f

  echo "Готово: $out"
  echo "SHA256: $sha"
}

verify_backup() {
  local file="$1"
  local key
  key=$(pass_file)
  [ -f "$key" ] || { echo "Ключ не найден: $key"; exit 1; }
  sha256sum -c "${file}.sha256" >/dev/null || { echo "SHA256 не сошёлся — архив повреждён"; exit 1; }
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass file:"$key" -in "$file" -out "$TMP/check.tar.gz"
  tar -tzf "$TMP/check.tar.gz" >/dev/null
  echo "Проверка пройдена: архив цел, шифрование снимается ключом, tar читается."
}

restore_backup() {
  local file="$1"
  [ -f "$file" ] || { echo "Файл не найден: $file"; exit 1; }
  verify_backup "$file"
  echo "=== Восстановление из $file ==="
  echo "ВНИМАНИЕ: это перезапишет ./config, ./certs, ./data/mail-state в $(pwd)"
  read -rp "Продолжить? (yes/N): " ok
  [ "$ok" = "yes" ] || { echo "Отменено"; exit 1; }

  openssl enc -d -aes-256-cbc -pbkdf2 -iter 600000 -pass file:"$(pass_file)" -in "$file" -out "$TMP/restore.tar.gz"
  tar -xzf "$TMP/restore.tar.gz" -C "$TMP"
  for d in config certs data/mail data/mail-state; do
    [ -e "$TMP/aether/$d" ] && rm -rf "./$d" && cp -a "$TMP/aether/$d" "./$d"
  done
  if [ -s "$TMP/aether/postgres.sql" ]; then
    docker compose up -d db
    sleep 5
    docker exec -i aether-db psql -U aether -d aether < "$TMP/aether/postgres.sql" >/dev/null \
      && echo "PostgreSQL восстановлен из дампа" \
      || echo "Предупреждение: не удалось восстановить PostgreSQL"
  fi
  docker compose up -d
  docker restart mailserver
  echo "Восстановлено. Ящики восстановятся из mailboxes.txt вручную: docker exec mailserver setup email add <ящик> '<пароль>'"
}

install_cron() {
  cat > /etc/cron.daily/aether-backup <<EOF
#!/usr/bin/env bash
cd "$(pwd)" && bash scripts/backup.sh >> /var/log/aether-backup.log 2>&1
EOF
  cat > /etc/cron.weekly/aether-verify <<EOF
#!/usr/bin/env bash
cd "$(pwd)" && latest=\$(ls -1t backups/aether-*.tar.gz.age | head -1) && bash scripts/backup.sh --verify "\$latest" >> /var/log/aether-backup.log 2>&1
EOF
  chmod +x /etc/cron.daily/aether-backup /etc/cron.weekly/aether-verify
  echo "Cron установлен: ежедневный бэкап, еженедельная проверка восстановления."
}

case "${1:-}" in
  "") create_backup ;;
  --verify) verify_backup "${2:?укажи файл бэкапа}" ;;
  --restore) restore_backup "${2:?укажи файл бэкапа}" ;;
  --install-cron) install_cron ;;
  *) echo "Неизвестный аргумент: $1 (см. заголовок скрипта)"; exit 1 ;;
esac
