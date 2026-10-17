#!/usr/bin/env bash
# install-mail.sh — поднятие почтового сервера на VPS за один запуск.
# Порты: 25 (приём) + 465/587/2525/2526/2527 (отправка). Веб-панель на поддомене с SSL.
set -euo pipefail

# ---------- проверки ----------
if [ "$(id -u)" -ne 0 ]; then echo "Запускай от root: sudo bash install-mail.sh"; exit 1; fi
if [ -f .env.mail ] && [ "${1:-}" != "--reinstall" ]; then
  echo "Сервер уже установлен (найден .env.mail). Переустановка: bash install-mail.sh --reinstall"
  exit 1
fi

echo "=== Установка почтового сервера ==="

# ---------- ввод данных ----------
read -rp "Домен почты (например example.com): " MAIL_DOMAIN
MAIL_DOMAIN=$(echo "$MAIL_DOMAIN" | tr '[:upper:]' '[:lower:]' | sed 's/^\.//; s/\.$//')
if ! echo "$MAIL_DOMAIN" | grep -qE '^[a-z0-9.-]+\.[a-z]{2,}$'; then
  echo "Некорректный домен: $MAIL_DOMAIN"; exit 1
fi

read -rp "Поддомен для админ-панели (например mailpanel): " PANEL_SUB
PANEL_SUB=$(echo "$PANEL_SUB" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]//g')
[ -z "$PANEL_SUB" ] && { echo "Поддомен не может быть пустым"; exit 1; }
PANEL_DOMAIN="${PANEL_SUB}.${MAIL_DOMAIN}"
MAIL_HOSTNAME="mail.${MAIL_DOMAIN}"

read -rp "Пароль администратора панели [сгенерирую случайный]: " ADMIN_PASS
[ -z "$ADMIN_PASS" ] && ADMIN_PASS=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9' | head -c 16)
if [ "${#ADMIN_PASS}" -lt 8 ]; then echo "Пароль минимум 8 символов"; exit 1; fi

SERVER_IP=$(curl -fsS4 ifconfig.me || curl -fsS4 api.ipify.org || echo "ВАШ_IP")

echo
echo "Домен почты:      $MAIL_DOMAIN"
echo "Панель будет на:  https://$PANEL_DOMAIN"
echo "Почтовый хост:    $MAIL_HOSTNAME (IP: $SERVER_IP)"
echo
read -rp "Всё верно? DNS A-записи mail.$MAIL_DOMAIN и $PANEL_DOMAIN уже указывают на $SERVER_IP? (y/N): " CONFIRM
[ "$CONFIRM" = "y" ] || { echo "Отменено. Сначала настрой DNS, потом запусти скрипт снова."; exit 1; }

# ---------- зависимости ----------
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y docker.io certbot ufw openssl curl
if ! docker compose version >/dev/null 2>&1; then
  mkdir -p /usr/local/lib/docker/cli-plugins
  curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64" \
    -o /usr/local/lib/docker/cli-plugins/docker-compose
  chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
fi

# ---------- конфиги ----------
mkdir -p data/mail data/mail-state data/db config certs edge/panel edge/nginx

ADMIN_HASH=$(python3 - "$ADMIN_PASS" <<'EOF'
import hashlib, os, sys
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha256", sys.argv[1].encode(), salt, 200_000)
print(f"pbkdf2${salt.hex()}${dk.hex()}")
EOF
)

API_KEY=$(openssl rand -hex 32)
DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
SESSION_SECRET=$(openssl rand -hex 32)

# Переменные подстановки docker compose (${MAIL_DOMAIN} и т.д. берутся отсюда)
cat > .env <<EOF
MAIL_DOMAIN=${MAIL_DOMAIN}
PANEL_DOMAIN=${PANEL_DOMAIN}
API_KEY=${API_KEY}
DB_PASSWORD=${DB_PASSWORD}
EOF

cat > .env.db <<EOF
POSTGRES_USER=aether
POSTGRES_DB=aether
POSTGRES_PASSWORD=${DB_PASSWORD}
EOF

cat > .env.api <<EOF
API_KEY=${API_KEY}
PANEL_ADMIN_HASH=${ADMIN_HASH}
PANEL_SESSION_SECRET=${SESSION_SECRET}
MAIL_DOMAIN=${MAIL_DOMAIN}
SECURE_COOKIE=true
EOF

cat > .env.mail <<EOF
ENABLE_OPENDKIM=1
ENABLE_OPENDMARC=1
ENABLE_FAIL2BAN=1
ENABLE_CLAMAV=0
ENABLE_RSPAMD=0
POSTMASTER_ADDRESS=admin@${MAIL_DOMAIN}
SSL_TYPE=manual
SSL_CERT_PATH=/etc/letsencrypt/live/${MAIL_HOSTNAME}/fullchain.pem
SSL_KEY_PATH=/etc/letsencrypt/live/${MAIL_HOSTNAME}/privkey.pem
EOF

cat > .env.panel <<EOF
PANEL_ADMIN_HASH=${ADMIN_HASH}
PANEL_SESSION_SECRET=${SESSION_SECRET}
MAIL_DOMAIN=${MAIL_DOMAIN}
PANEL_DOMAIN=${PANEL_DOMAIN}
EOF

# Рендерим nginx-конфиг из шаблона (исходник с плейсхолдером сохраняем)
if [ ! -f edge/nginx/nginx.conf.template ]; then
  cp edge/nginx/nginx.conf edge/nginx/nginx.conf.template
fi
sed "s/__MAIL_HOSTNAME__/${MAIL_HOSTNAME}/g" edge/nginx/nginx.conf.template > edge/nginx/nginx.conf

# ---------- файрвол ----------
ufw allow 22/tcp   >/dev/null
ufw allow 25/tcp   >/dev/null
ufw allow 465/tcp  >/dev/null
ufw allow 587/tcp  >/dev/null
ufw allow 2525:2527/tcp >/dev/null
ufw allow 80/tcp   >/dev/null
ufw allow 443/tcp  >/dev/null
ufw --force enable >/dev/null

# ---------- SSL ----------
echo "=== Получение SSL-сертификатов (нужен открытый порт 80) ==="
certbot certonly --standalone --non-interactive --agree-tos -m "admin@${MAIL_DOMAIN}" \
  -d "${MAIL_HOSTNAME}" -d "${PANEL_DOMAIN}" || {
  echo "!!! certbot не смог получить сертификаты (DNS ещё не пропагировал? порт 80 закрыт?)."
  echo "!!! Запускаюсь с самоподписанными — отправка в спам почти гарантирована."
  mkdir -p "certs/live/${MAIL_HOSTNAME}"
  openssl req -x509 -newkey rsa:4096 -keyout "certs/live/${MAIL_HOSTNAME}/privkey.pem" \
    -out "certs/live/${MAIL_HOSTNAME}/fullchain.pem" -days 3650 -nodes \
    -subj "/CN=${MAIL_HOSTNAME}" 2>/dev/null
}
mkdir -p "certs/live/${MAIL_HOSTNAME}"
[ -f "certs/live/${MAIL_HOSTNAME}/fullchain.pem" ] || {
  openssl req -x509 -newkey rsa:4096 -keyout "certs/live/${MAIL_HOSTNAME}/privkey.pem" \
    -out "certs/live/${MAIL_HOSTNAME}/fullchain.pem" -days 3650 -nodes \
    -subj "/CN=${MAIL_HOSTNAME}" 2>/dev/null
}

# ---------- запуск ----------
echo "=== Запуск контейнеров ==="
docker compose pull
docker compose up -d --build

echo "=== Ожидание готовности почтового сервера ==="
for i in $(seq 1 30); do
  docker exec mailserver true 2>/dev/null && break
  sleep 2
done
sleep 10

echo "=== Ожидание готовности Go API и PostgreSQL ==="
for i in $(seq 1 45); do
  if docker exec aether-api wget -qO- http://127.0.0.1:8080/healthz 2>/dev/null | grep -q '"status":"ok"'; then
    echo "API готов"
    break
  fi
  if [ "$i" = "45" ]; then
    echo "Предупреждение: API не поднялся за 90 секунд, смотри: docker compose logs api"
  fi
  sleep 2
done

# ---------- DKIM ----------
docker exec mailserver setup config dkim || echo "Предупреждение: DKIM не сгенерировался"

# ---------- админский ящик ----------
docker exec mailserver setup email add "admin@${MAIL_DOMAIN}" "${ADMIN_PASS}" 2>/dev/null \
  || docker exec mailserver setup email update "admin@${MAIL_DOMAIN}" "${ADMIN_PASS}" \
  || echo "Предупреждение: не удалось создать admin@${MAIL_DOMAIN}"

# ---------- автообновление сертификатов ----------
cat > /etc/cron.daily/mail-cert-renew <<EOF
#!/usr/bin/env bash
certbot renew --quiet --deploy-hook "docker restart mailserver mail-nginx"
EOF
chmod +x /etc/cron.daily/mail-cert-renew

DKIM_TXT=$(cat "config/opendkim/keys/${MAIL_DOMAIN}/mail.txt" 2>/dev/null | tr -d '\n' || echo "не найден")

cat <<EOF

============================================================
ГОТОВО!
  Новая панель (Next.js): https://${PANEL_DOMAIN}/dashboard
  Старая панель (письма, DNS): https://${PANEL_DOMAIN}/legacy/

Данные администратора:
  Пароль панели: ${ADMIN_PASS}
  Ящик:          admin@${MAIL_DOMAIN} (пароль тот же)

Порты отправки: 465, 587, 2525, 2526, 2527
Порт приёма:    25

Обязательно добавь DNS-записи:
  A     mail            → ${SERVER_IP}
  A     ${PANEL_DOMAIN}  → ${SERVER_IP}
  MX    ${MAIL_DOMAIN}   → 10 mail.${MAIL_DOMAIN}
  TXT   ${MAIL_DOMAIN}   → v=spf1 mx -all
  TXT   _dmarc           → v=DMARC1; p=quarantine; rua=mailto:admin@${MAIL_DOMAIN}
  TXT   mail._domainkey  → ${DKIM_TXT}

Полный список записей есть в панели: https://${PANEL_DOMAIN}/dns
Сохрани этот вывод — пароль больше нигде не показывается!
============================================================
EOF
