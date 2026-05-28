#!/usr/bin/env bash
set -e

# ====================
# CONFIG & FUNCTIONS
# ====================

REMOTE_CONF_BASE="https://vps.fio.link/conf"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
LOG_FILE="/var/log/add_static_site.log"
USER_NGINX="nginx"

mycurl() { curl -fsSL -A "$CURL_UA" "$@"; }

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

usage() {
  echo "Usage: add-site-static-v2.sh -d domain.com -ssl le|self|none [-http3]"
  exit 1
}

is_valid_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

get_default_username() {
  local domain="$1"
  domain=$(echo "$domain" | sed 's|^https\?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]')
  local name="${domain//./}"
  name="$(echo "$name" | sed 's/[^a-z0-9]//g')"
  echo "${name:0:32}"
}

# ====================
# PARSE ARGUMENTS
# ====================

DOMAIN=""
SSL_TYPE="none"
HTTP3="off"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -ssl) SSL_TYPE="$2"; shift 2 ;;
    -http3) HTTP3="on"; shift ;;
    *) usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage
is_valid_domain "$DOMAIN" || { echo "Invalid domain: $DOMAIN"; exit 1; }

# ====================
# USER SELECTION FLOW
# ====================

DEFAULT_USER="$(get_default_username "$DOMAIN")"

echo ""
echo "Domain: $DOMAIN (static)"
echo ""
echo "Assign to which user?"
echo "  1) Create new user [$DEFAULT_USER]"
echo "  2) Use existing user"
echo ""
read -rp "Choice [1]: " USER_CHOICE
USER_CHOICE="${USER_CHOICE:-1}"

CREATE_NEW_USER=true

if [[ "$USER_CHOICE" == "2" ]]; then
  CREATE_NEW_USER=false

  mapfile -t EXISTING_USERS < <(awk -F: '$3 >= 1000 && $1 != "nobody" && $1 != "nfsnobody" {print $1}' /etc/passwd)

  if [[ ${#EXISTING_USERS[@]} -eq 0 ]]; then
    echo "[x] No existing users found. Creating new user instead."
    CREATE_NEW_USER=true
  else
    echo ""
    echo "Available users:"
    for i in "${!EXISTING_USERS[@]}"; do
      echo "  $((i+1))) ${EXISTING_USERS[$i]}"
    done
    echo ""
    read -rp "Select user [1]: " USER_IDX
    USER_IDX="${USER_IDX:-1}"
    USER="${EXISTING_USERS[$((USER_IDX-1))]}"

    if [[ -z "$USER" ]]; then
      echo "[x] Invalid selection. Exiting."
      exit 1
    fi
    echo "[✓] Using existing user: $USER"
  fi
fi

if [[ "$CREATE_NEW_USER" == true ]]; then
  read -rp "Username [$DEFAULT_USER]: " INPUT_USER
  USER="${INPUT_USER:-$DEFAULT_USER}"
  USER="$(echo "$USER" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')"
  USER="${USER:0:32}"

  if id "$USER" &>/dev/null; then
    echo "[!] User '$USER' already exists. Switching to existing user mode."
    CREATE_NEW_USER=false
  fi
fi

# ====================
# SETUP VARS
# ====================

USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN/public_html"
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
VHOST_URL="$REMOTE_CONF_BASE/nginx/custom-vhost-static.conf"

# ====================
# CREATE USER & DIRS
# ====================

if [[ "$CREATE_NEW_USER" == true ]]; then
  log "Creating user $USER..."
  useradd -m -d "$USER_HOME" -s /bin/bash "$USER"
else
  log "Using existing user $USER"
fi

mkdir -p "$SITE_DIR"
mkdir -p "$USER_HOME/logs/$DOMAIN/nginx"

chown -R "$USER:$USER" "$USER_HOME"
chmod 711 "$USER_HOME"
chmod 755 "$USER_HOME/$DOMAIN" "$SITE_DIR"

if [[ ! -f "$SITE_DIR/index.html" ]]; then
cat > "$SITE_DIR/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>$DOMAIN</title>
</head>
<body>
  <h1>$DOMAIN</h1>
  <p>Static site ready.</p>
</body>
</html>
EOF
chown "$USER:$USER" "$SITE_DIR/index.html"
fi

# ====================
# CONFIGURE NGINX
# ====================

log "Downloading NGINX static vhost config..."
mycurl "$VHOST_URL" > "$NGINX_CONF"

sed -i "s|\$DOMAIN|$DOMAIN|g; s|\$USER|$USER|g" "$NGINX_CONF"
sed -i "s|/home/$USER/logs/nginx/|/home/$USER/logs/$DOMAIN/nginx/|g" "$NGINX_CONF"

ln -sf "$NGINX_CONF" "$NGINX_LINK"

# ====================
# SSL HANDLING
# ====================

if [[ "$SSL_TYPE" == "le" ]]; then
  log ">> [LE] Preparing dummy certificate..."

  DUMMY_DIR="/etc/ssl/selfsigned"
  DUMMY_CERT="$DUMMY_DIR/$DOMAIN.crt"
  DUMMY_KEY="$DUMMY_DIR/$DOMAIN.key"
  mkdir -p "$DUMMY_DIR"

  if [[ ! -f "$DUMMY_CERT" || ! -f "$DUMMY_KEY" ]]; then
    openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
      -keyout "$DUMMY_KEY" \
      -out "$DUMMY_CERT" \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$DOMAIN"
    log "[✓] Dummy SSL generated"
  fi

  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 ssl;|listen [::]:443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$NGINX_CONF"

  if [[ "$HTTP3" == "on" ]]; then
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 quic;|listen 443 quic;|g" "$NGINX_CONF"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 quic;|listen [::]:443 quic;|g" "$NGINX_CONF"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http3 on;|http3 on;|g" "$NGINX_CONF"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*add_header Alt-Svc.*|add_header Alt-Svc 'h3=\":443\"; ma=86400' always;|g" "$NGINX_CONF"
  else
    sed -i "/#LE-SSL.*listen 443 quic/d" "$NGINX_CONF"
    sed -i "/#LE-SSL.*\[::\]:443 quic/d" "$NGINX_CONF"
    sed -i "/#LE-SSL.*http3/d" "$NGINX_CONF"
    sed -i "/#LE-SSL.*Alt-Svc/d" "$NGINX_CONF"
  fi

  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $DUMMY_CERT;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $DUMMY_KEY;|g" "$NGINX_CONF"

  nginx -t && systemctl reload nginx || { log "[x] NGINX invalid"; exit 1; }

  if dig +short www.$DOMAIN 2>/dev/null | grep -qE '.'; then
    REQUEST_WWW=true
  else
    REQUEST_WWW=false
  fi

  if [[ "$REQUEST_WWW" == true ]]; then
    certbot certonly --nginx --non-interactive --agree-tos --email "admin@$DOMAIN" \
      -d "$DOMAIN" -d "www.$DOMAIN" || \
    certbot certonly --nginx --non-interactive --agree-tos --email "admin@$DOMAIN" \
      -d "$DOMAIN" || { log "[x] Certbot failed"; exit 1; }
  else
    certbot certonly --nginx --non-interactive --agree-tos --email "admin@$DOMAIN" \
      -d "$DOMAIN" || { log "[x] Certbot failed"; exit 1; }
  fi

  REAL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  REAL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

  if [[ -f "$REAL_CERT" && -f "$REAL_KEY" ]]; then
    sed -i "s|ssl_certificate .*|ssl_certificate $REAL_CERT;|g" "$NGINX_CONF"
    sed -i "s|ssl_certificate_key .*|ssl_certificate_key $REAL_KEY;|g" "$NGINX_CONF"
    nginx -t && systemctl reload nginx
    log "[✓] Let's Encrypt SSL active"
  else
    log "[x] Cert files not found"
    exit 1
  fi

  CRON_RENEW="/etc/cron.d/certbot_renew"
  if [[ ! -f "$CRON_RENEW" ]]; then
    echo '0 3 * * * root certbot renew --quiet --post-hook "systemctl reload nginx"' > "$CRON_RENEW"
  fi

elif [[ "$SSL_TYPE" == "self" ]]; then
  log ">> [SELF] Self-signed certificate..."

  DUMMY_DIR="/etc/ssl/selfsigned"
  DUMMY_CERT="$DUMMY_DIR/$DOMAIN.crt"
  DUMMY_KEY="$DUMMY_DIR/$DOMAIN.key"
  mkdir -p "$DUMMY_DIR"

  if [[ ! -f "$DUMMY_CERT" || ! -f "$DUMMY_KEY" ]]; then
    openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
      -keyout "$DUMMY_KEY" \
      -out "$DUMMY_CERT" \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$DOMAIN"
  fi

  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 ssl;|listen [::]:443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $DUMMY_CERT;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $DUMMY_KEY;|g" "$NGINX_CONF"

  sed -i "/#LE-SSL.*listen 443 quic/d" "$NGINX_CONF"
  sed -i "/#LE-SSL.*\[::\]:443 quic/d" "$NGINX_CONF"
  sed -i "/#LE-SSL.*http3/d" "$NGINX_CONF"
  sed -i "/#LE-SSL.*Alt-Svc/d" "$NGINX_CONF"

  nginx -t && systemctl reload nginx || { log "[x] NGINX invalid"; exit 1; }
  log "[✓] Self-signed SSL active"

elif [[ "$SSL_TYPE" == "none" ]]; then
  log ">> [SSL] Disabled (HTTP only)"
  sed -i '/#LE-SSL/d' "$NGINX_CONF"
  nginx -t && systemctl reload nginx
fi

# ============================
# Filemanager
# ============================
FB_HOST="http://127.0.0.1:2222"
FB_TOKEN_FILE="/root/.filebrowser_token"
FB_PASS="(skipped)"

if [[ -f "$FB_TOKEN_FILE" ]]; then
  TOKEN=$(cat "$FB_TOKEN_FILE")
  FB_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)

  FB_EXISTING=$(curl -s -X GET "$FB_HOST/api/users" \
    -H "X-Auth: $TOKEN" \
    -H "Content-Type: application/json" | jq -r ".[] | select(.username==\"$USER\") | .username" 2>/dev/null)

  if [[ "$FB_EXISTING" == "$USER" ]]; then
    log "[FB] User '$USER' already exists. Skipping."
    FB_PASS="(existing - unchanged)"
  else
    log "[FB] Creating Filebrowser user: $USER"

    FB_ADMIN_PASS=""
    if [[ -f /root/.filebrowser_admin ]]; then
      FB_ADMIN_PASS=$(jq -r '.password' /root/.filebrowser_admin)
    fi

    FB_TMP="/tmp/fb-payload-$USER.json"
    jq -n \
      --arg user "$USER" \
      --arg pass "$FB_PASS" \
      --arg adminpass "$FB_ADMIN_PASS" \
      '{
        "what": "user",
        "which": [],
        "data": {
          "username": $user,
          "password": $pass,
          "scope": ("/"+$user),
          "locale": "en",
          "lockPassword": false,
          "viewMode": "list",
          "singleClick": false,
          "redirectAfterCopyMove": false,
          "hideDotfiles": false,
          "dateFormat": false,
          "aceEditorTheme": "",
          "commands": [],
          "rules": [],
          "sorting": {"by":"name","asc":false},
          "perm": {
            "admin": false,
            "execute": true,
            "create": true,
            "rename": true,
            "modify": true,
            "delete": true,
            "share": true,
            "download": true
          }
        },
        "current_password": $adminpass
      }' > "$FB_TMP"

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
      -X POST "$FB_HOST/api/users" \
      -H "X-Auth: $TOKEN" \
      -H "Content-Type: application/json" \
      -d @"$FB_TMP")

    if [[ "$HTTP_CODE" == "201" || "$HTTP_CODE" == "200" ]]; then
      log "[FB] User added successfully"
    else
      log "[FB] ERROR creating user (HTTP $HTTP_CODE)"
    fi

    rm -f "$FB_TMP"
  fi
else
  log "[FB] Token file not found, skipping"
fi

# ====================
# LOGROTATE
# ====================

cat >/etc/logrotate.d/$USER.conf <<EOF
/home/$USER/logs/*/*.log
/home/$USER/logs/*/*/*.log {
    su root root
    daily
    missingok
    rotate 30
    dateext
    dateformat -%Y-%m-%d
    create 0640 $USER_NGINX $USER
    postrotate
      /etc/init.d/nginx reload &>/dev/null || true
    endscript
}
EOF

log "[✓] Logrotate configured"

# ====================
# DONE
# ====================

log "[✓] Static site $DOMAIN created successfully"

echo ""
echo "--------------------------------------------"
echo "Site:           http${SSL_TYPE:+s}://$DOMAIN"
echo "User:           $USER"
echo "Root Folder:    $SITE_DIR"
echo "Logs:           $USER_HOME/logs/$DOMAIN/nginx/"
echo "Nginx Conf:     $NGINX_CONF"
echo "File Manager:   $FB_HOST"
echo "FM Username:    $USER"
echo "FM Password:    $FB_PASS"
echo "--------------------------------------------"

# ====================
# SAVE SUMMARY
# ====================

SUMMARY_FILE="$USER_HOME/.summary-$DOMAIN.md"

cat > "$SUMMARY_FILE" <<EOF
# $DOMAIN

Created: $(date +'%Y-%m-%d %H:%M:%S')
Type: Static Site
User: $USER ($([ "$CREATE_NEW_USER" == true ] && echo "new" || echo "existing"))

## Server

| Key | Value |
|-----|-------|
| Domain | $DOMAIN |
| User | $USER |
| Root | $SITE_DIR |
| Logs | $USER_HOME/logs/$DOMAIN/nginx/ |
| SSL | ${SSL_TYPE:-none} |

## File Manager

| Key | Value |
|-----|-------|
| URL | https://$DOMAIN/fm |
| Username | $USER |
| Password | $FB_PASS |
EOF

chmod 600 "$SUMMARY_FILE"
chown "$USER:$USER" "$SUMMARY_FILE"
log "[✓] Summary saved → $SUMMARY_FILE"
