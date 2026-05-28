#!/usr/bin/env bash
set -e

# ====================
# CONFIG & FUNCTIONS
# ====================

REMOTE_CONF_BASE="https://vps.fio.link/conf"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
LOG_FILE="/var/log/add_static_site.log"
USER_NGINX="nginx"

VHOST_URL="$REMOTE_CONF_BASE/nginx/custom-vhost-static.conf"

mycurl() { curl -fsSL -A "$CURL_UA" "$@"; }

log() {
  mkdir -p "$(dirname "$LOG_FILE")"
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

usage() {
  echo "Usage: add-site-static.sh -d domain.com -ssl le|self|none"
  exit 1
}

is_valid_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

get_user_from_domain() {
  local domain="$1"
  local maxlen=32

  # Clean domain
  domain=$(echo "$domain" | sed 's|^https\?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]')
  
  IFS='.' read -ra p <<< "$domain"
  local n=${#p[@]}
  (( n < 2 )) && return 1

  # Detect TLD Parts (Heuristic for .my.id, .co.id, etc.)
  local tld_parts=1
  if (( n >= 3 )); then
      local p2="${p[$((n-2))]}"
      if [[ " co my web ac go or biz net com sch org " =~ " $p2 " ]]; then
          tld_parts=2
      fi
  fi

  local base_idx=$(( n - tld_parts - 1 ))
  if (( base_idx < 0 )); then
      echo "${p[0]:0:maxlen}"
      return 0
  fi

  # Build name: BASE-SUB-SUBSUB
  local name="${p[$base_idx]}"
  for (( i=base_idx-1; i>=0; i-- )); do
      name="${name}-${p[$i]}"
  done

  # Final sanitization
  name="$(echo "$name" | sed 's/[^a-z0-9-]/-/g; s/-\+/-/g; s/^-//; s/-$//')"
  echo "${name:0:maxlen}"
}

# ====================
# PARSE ARGUMENTS
# ====================

DOMAIN=""
SSL_TYPE="none"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -ssl) SSL_TYPE="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage
is_valid_domain "$DOMAIN" || { echo "Invalid domain: $DOMAIN"; exit 1; }

# ====================
# SETUP VARS
# ====================

USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN/public_html"

NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
LOG_DIR="$USER_HOME/logs/$DOMAIN/nginx"

# ====================
# CREATE USER & DIR
# ====================

if ! id "$USER" &>/dev/null; then
  log "Creating user $USER..."
  useradd -m -d "$USER_HOME" -s /bin/bash "$USER"
else
  log "User exists: $USER"
fi

mkdir -p "$SITE_DIR" "$LOG_DIR"
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

ln -sf "$NGINX_CONF" "$NGINX_LINK"

# ====================
# SSL HANDLING
# ====================

if [[ "$SSL_TYPE" == "le" ]]; then
  log ">> [LE] Preparing dummy certificate for initial NGINX config..."

  DUMMY_DIR="/etc/ssl/selfsigned"
  DUMMY_CERT="$DUMMY_DIR/$DOMAIN.crt"
  DUMMY_KEY="$DUMMY_DIR/$DOMAIN.key"
  mkdir -p "$DUMMY_DIR"

  if [[ ! -f "$DUMMY_CERT" || ! -f "$DUMMY_KEY" ]]; then
    openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
      -keyout "$DUMMY_KEY" \
      -out "$DUMMY_CERT" \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$DOMAIN"
    log "[✓] Dummy SSL generated for $DOMAIN"
  else
    log "[i] Dummy SSL already exists for $DOMAIN"
  fi

  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 quic;|listen 443 quic;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \\[::\\]:443 quic;|listen [::]:443 quic;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \\[::\\]:443 ssl;|listen [::]:443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http3 off;|http3 off;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $DUMMY_CERT;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $DUMMY_KEY;|g" "$NGINX_CONF"

  grep -q "ssl_certificate " "$NGINX_CONF" || {
    log "[x] ERROR: ssl_certificate not found after sed"
    exit 1
  }

  nginx -t && systemctl reload nginx || {
    log "[x] ERROR: NGINX invalid after dummy cert"
    exit 1
  }

  # ============================
  # AUTO DETECT WWW DNS
  # ============================
  if command -v dig >/dev/null 2>&1 && dig +short "www.$DOMAIN" | grep -q .; then
    REQUEST_WWW=true
    log ">> DNS www.$DOMAIN detected → requesting www + non-www"
  else
    REQUEST_WWW=false
    log ">> No DNS for www.$DOMAIN → requesting non-www only"
  fi

  # ============================
  # REQUEST LET'S ENCRYPT
  # ============================
  if [[ "$REQUEST_WWW" == true ]]; then
    certbot certonly --nginx --non-interactive --agree-tos \
      --email "admin@$DOMAIN" \
      -d "$DOMAIN" -d "www.$DOMAIN" || \
    certbot certonly --nginx --non-interactive --agree-tos \
      --email "admin@$DOMAIN" -d "$DOMAIN" || {
        log "[x] Certbot failed. Keeping dummy cert."
        exit 1
      }
  else
    certbot certonly --nginx --non-interactive --agree-tos \
      --email "admin@$DOMAIN" -d "$DOMAIN" || {
        log "[x] Certbot failed. Keeping dummy cert."
        exit 1
      }
  fi

  # ============================
  # APPLY REAL CERT
  # ============================
  REAL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  REAL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

  [[ -f "$REAL_CERT" && -f "$REAL_KEY" ]] || {
    log "[x] ERROR: LE cert files not found"
    exit 1
  }

  sed -i "s|ssl_certificate .*|ssl_certificate $REAL_CERT;|g" "$NGINX_CONF"
  sed -i "s|ssl_certificate_key .*|ssl_certificate_key $REAL_KEY;|g" "$NGINX_CONF"

  nginx -t && systemctl reload nginx || {
    log "[x] ERROR: NGINX invalid after real cert"
    exit 1
  }

  log "[✓] Let's Encrypt SSL ACTIVE"

elif [[ "$SSL_TYPE" == "self" ]]; then
  log ">> [SELF] Preparing self-signed certificate..."

  DUMMY_DIR="/etc/ssl/selfsigned"
  DUMMY_CERT="$DUMMY_DIR/$DOMAIN.crt"
  DUMMY_KEY="$DUMMY_DIR/$DOMAIN.key"
  mkdir -p "$DUMMY_DIR"

  [[ -f "$DUMMY_CERT" && -f "$DUMMY_KEY" ]] || \
    openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
      -keyout "$DUMMY_KEY" \
      -out "$DUMMY_CERT" \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$DOMAIN"

  sed -i "s|^[[:space:]]*#LE-SSL.*|&|g" "$NGINX_CONF"
  sed -i "s|#LE-SSL listen 443 ssl;|listen 443 ssl;|g" "$NGINX_CONF"
  sed -i "s|#LE-SSL listen \\[::\\]:443 ssl;|listen [::]:443 ssl;|g" "$NGINX_CONF"
  sed -i "s|#LE-SSL http2 on;|http2 on;|g" "$NGINX_CONF"
  sed -i "s|#LE-SSL ssl_certificate .*|ssl_certificate $DUMMY_CERT;|g" "$NGINX_CONF"
  sed -i "s|#LE-SSL ssl_certificate_key .*|ssl_certificate_key $DUMMY_KEY;|g" "$NGINX_CONF"

  nginx -t && systemctl reload nginx || {
    log "[x] ERROR: NGINX invalid with self-signed"
    exit 1
  }

  log "[✓] Self-signed SSL ACTIVE"

elif [[ "$SSL_TYPE" == "none" ]]; then
  log ">> [SSL] Disabled (HTTP only)"
  sed -i '/#LE-SSL/d' "$NGINX_CONF"
fi

# ============================
# Filemanager
# ============================
FB_HOST="http://127.0.0.1:2222"
FB_TOKEN_FILE="/root/.filebrowser_token"

  if [[ ! -f "$FB_TOKEN_FILE" ]]; then
    log "[FB] ERROR: Token file not found → $FB_TOKEN_FILE"
    log "[FB] Install script must generate token first. Skipping."
    return 1
  fi

  TOKEN=$(cat "$FB_TOKEN_FILE")
  FB_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)

  log "[FB] Creating Filebrowser user: $USER"

  FB_ADMIN_PASS=""
  if [[ -f /root/.filebrowser_admin ]]; then
    FB_ADMIN_PASS=$(jq -r '.password' /root/.filebrowser_admin)
  fi

  FB_TMP="/tmp/fb-payload-$USER.json"
  jq -nc \
    --arg user "$USER" \
    --arg pass "$FB_PASS" \
    --arg adminpass "$FB_ADMIN_PASS" \
    '{what:"user",which:[],data:{username:$user,password:$pass,scope:("/"+$user),locale:"en",lockPassword:false,viewMode:"list",singleClick:false,redirectAfterCopyMove:false,hideDotfiles:false,dateFormat:false,aceEditorTheme:"",commands:[],rules:[],sorting:{by:"name",asc:false},perm:{admin:false,execute:true,create:true,rename:true,modify:true,delete:true,share:true,download:true}},current_password:$adminpass}' > "$FB_TMP"

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

# ====================
# LOGROTATE
# ====================
log ">> Creating logrotate config..."

cat >/etc/logrotate.d/$USER.conf <<EOF
/home/$USER/logs/$DOMAIN/nginx/*.log {
    daily
    missingok
    rotate 30
    dateext
    create 0640 $USER_NGINX $USER
    postrotate
      /etc/init.d/nginx reload &>/dev/null || true
    endscript
}
EOF

# ====================
# DONE
# ====================
log "[✓] Static site created successfully"

echo "--------------------------------------------"
echo "Site:        http${SSL_TYPE:+s}://$DOMAIN"
echo "User:        $USER"
echo "Root Folder: $SITE_DIR"
echo "Nginx Conf:  $NGINX_CONF"
echo "Logs:        $LOG_DIR"
echo "File Manager:   $FB_HOST"
echo "FM Username:    $USER"
echo "FM Password:    $FB_PASS"
echo "--------------------------------------------"

# ====================
# SAVE SUMMARY
# ====================

SUMMARY_FILE="$USER_HOME/.summary.md"

cat > "$SUMMARY_FILE" <<EOF
# $DOMAIN

Created: $(date +'%Y-%m-%d %H:%M:%S')
Type: Static Site

## Server

| Key | Value |
|-----|-------|
| Domain | $DOMAIN |
| User | $USER |
| Root | $SITE_DIR |
| SSL | ${SSL_TYPE:-none} |
| Nginx Conf | $NGINX_CONF |
| Logs | $LOG_DIR |

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
