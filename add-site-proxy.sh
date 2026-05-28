#!/usr/bin/env bash
set -e

# add-site-proxy.sh
# Production-ready: routes mode (subpath) + LB mode + SSL (le|self|none)

# ====================
# CONFIG
# ====================
REMOTE_CONF_BASE="https://vps.fio.link/conf"
VHOST_URL="$REMOTE_CONF_BASE/nginx/proxy-vhost.conf"
CURL_UA="Mozilla/5.0"
LOG_FILE="/var/log/add_proxy_site.log"

mycurl() { curl -fsSL -A "$CURL_UA" "$@"; }
log() { mkdir -p "$(dirname "$LOG_FILE")"; echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"; }

usage() {
cat <<EOF
Usage:
 LB mode:
   add-site-proxy.sh -d domain.com -backends 'ip:port,https://ip:443' -ssl le|self|none

 Routes mode:
   add-site-proxy.sh -d domain.com -routes '/api=ip:port,/app=ip:port' \\
     [-root-mode 403|redirect|proxy] \\
     [-root-target /app] \\
     [-root-backend ip:port] \\
     -ssl le|self|none
EOF
exit 1
}

# ====================
# DEFAULT VARS
# ====================
DOMAIN=""
BACKENDS=""
ROUTES=""
SSL_TYPE="none"

ROOT_MODE="403"
ROOT_TARGET=""
ROOT_BACKEND=""

# ====================
# ARG PARSE
# ====================
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -backends) BACKENDS="$2"; shift 2 ;;
    -routes) ROUTES="$2"; shift 2 ;;
    -ssl) SSL_TYPE="${2,,}"; shift 2 ;;
    -root-mode) ROOT_MODE="$2"; shift 2 ;;
    -root-target) ROOT_TARGET="$2"; shift 2 ;;
    -root-backend) ROOT_BACKEND="$2"; shift 2 ;;
    -vhost-url) VHOST_URL="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage
[[ -z "$ROUTES" && -z "$BACKENDS" ]] && BACKENDS="127.0.0.1:8080"

# ====================
# DOMAIN → USER
# ====================
get_user_from_domain() {
  local domain="$1"
  local maxlen=32
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
# 
# ====================
USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
LOG_DIR="/home/$USER/logs/nginx"
UPSTREAM="${DOMAIN}_upstream"

# ====================
# USER & DIR
# ====================
if ! id "$USER" &>/dev/null; then
  useradd -m "$USER" || true
  log "Created user $USER"
else
  log "User exists: $USER"
fi

mkdir -p "$LOG_DIR"
chown -R "$USER:$USER" "/home/$USER" || true

# ====================
# TEMPLATE
# ====================
log "Downloading vhost template from $VHOST_URL"
mycurl "$VHOST_URL" > "$NGINX_CONF" || { log "Failed to download vhost template"; exit 1; }

UPSTREAM_BLOCK=$(mktemp)
ROOT_BLOCK=$(mktemp)
ROUTES_BLOCK=$(mktemp)
DEFAULT_BLOCK=$(mktemp)
HEALTHZ_BLOCK=$(mktemp)
trap 'rm -f "$UPSTREAM_BLOCK" "$ROOT_BLOCK" "$ROUTES_BLOCK" "$DEFAULT_BLOCK" "$HEALTHZ_BLOCK"' EXIT
printf "map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }\n" > "$UPSTREAM_BLOCK"

# ====================
# BUILD BLOCKS
# ====================
if [[ -n "$ROUTES" ]]; then
  log "ROUTES mode"
  IFS=',' read -ra ARR <<< "$ROUTES"
  for r in "${ARR[@]}"; do
    pair="$(echo "$r" | xargs)"
    path="${pair%%=*}"
    backend="${pair#*=}"
    [[ "${path: -1}" != "/" ]] && path="${path}/"

cat >> "$ROUTES_BLOCK" <<EOF

location $path {
  include /etc/nginx/includes/be-proxy.conf;
  proxy_pass http://$backend/;
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;
  proxy_set_header Upgrade \$http_upgrade;
  proxy_set_header Connection \$connection_upgrade;
  proxy_buffering off;
}
EOF
  done

  case "$ROOT_MODE" in
    403)
cat >> "$ROOT_BLOCK" <<'EOF'

location = / { return 403; }
EOF
    ;;
    redirect)
      : "${ROOT_TARGET:=/}"
cat >> "$ROOT_BLOCK" <<EOF

location = / { return 302 $ROOT_TARGET; }
EOF
    ;;
    proxy)
      if [[ -z "$ROOT_BACKEND" ]]; then
        log "ROOT_MODE=proxy but ROOT_BACKEND empty; aborting"
        exit 1
      fi
cat >> "$ROOT_BLOCK" <<EOF

location = / {
  include /etc/nginx/includes/be-proxy.conf;
  proxy_pass http://$ROOT_BACKEND/;
  proxy_http_version 1.1;
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto \$scheme;
  proxy_buffering off;
}
EOF
    ;;
    *)
      log "Unknown ROOT_MODE=$ROOT_MODE, defaulting to 403"
cat >> "$ROOT_BLOCK" <<'EOF'

location = / { return 403; }
EOF
    ;;
  esac

  PROTO="http"

else
  log "LB mode"
  echo "upstream $UPSTREAM { least_conn;" >> "$UPSTREAM_BLOCK"

  PROTO="http"
  IFS=',' read -ra ARR <<< "$BACKENDS"
  for b in "${ARR[@]}"; do
    b_trimmed="$(echo "$b" | xargs)"
    server_addr="${b_trimmed#http://}"
    server_addr="${server_addr#https://}"
    echo "  server $server_addr;" >> "$UPSTREAM_BLOCK"
    if [[ "$b_trimmed" == https://* || "${server_addr##*:}" == "443" ]]; then
      PROTO="https"
    fi
  done
  echo "}" >> "$UPSTREAM_BLOCK"

cat >> "$DEFAULT_BLOCK" <<EOF

location / {
  include /etc/nginx/includes/be-proxy.conf;
  proxy_pass $PROTO://$UPSTREAM;
  proxy_http_version 1.1;
  proxy_set_header Upgrade \$http_upgrade;
  proxy_set_header Connection \$connection_upgrade;  
  proxy_set_header Host \$host;
  proxy_set_header X-Real-IP \$remote_addr;
  proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  proxy_buffering off;
}
EOF

cat >> "$HEALTHZ_BLOCK" <<'EOF'

location /healthz {
  access_log off;
  return 200 'ok';
  add_header Content-Type text/plain;
}
EOF

fi

# ====================
# INJECT INTO TEMPLATE
# ====================
# Upstream
sed -i "/__UPSTREAM_BLOCK__/ { r $UPSTREAM_BLOCK
  d
}" "$NGINX_CONF"

if [[ -s "$ROOT_BLOCK" ]]; then
  sed -i "/__ROOT_BLOCK__/ { r $ROOT_BLOCK
    d
  }" "$NGINX_CONF"
else
  sed -i "/__ROOT_BLOCK__/d" "$NGINX_CONF"
fi

if [[ -s "$ROUTES_BLOCK" ]]; then
  sed -i "/__ROUTES_BLOCK__/ { r $ROUTES_BLOCK
    d
  }" "$NGINX_CONF"
else
  sed -i "/__ROUTES_BLOCK__/d" "$NGINX_CONF"
fi

if [[ -s "$DEFAULT_BLOCK" ]]; then
  sed -i "/__DEFAULT_PROXY_BLOCK__/ { r $DEFAULT_BLOCK
    d
  }" "$NGINX_CONF"
else
  sed -i "/__DEFAULT_PROXY_BLOCK__/d" "$NGINX_CONF"
fi

if [[ -s "$HEALTHZ_BLOCK" ]]; then
  sed -i "/__HEALTHZ_BLOCK__/ { r $HEALTHZ_BLOCK
    d
  }" "$NGINX_CONF"
else
  sed -i "/__HEALTHZ_BLOCK__/d" "$NGINX_CONF"
fi

sed -i "s|\$DOMAIN|$DOMAIN|g; s|\$USER|$USER|g" "$NGINX_CONF"

ln -sf "$NGINX_CONF" "$NGINX_LINK"

# ====================
# SSL HANDLING (exact logic you specified)
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

# ====================
# SUMMARY
# ====================
echo "--------------------------------------------------"
echo " PROXY SITE CREATED SUCCESSFULLY"
echo "--------------------------------------------------"
echo " Domain        : $DOMAIN"
if [[ -n "$ROUTES" ]]; then
  echo " Mode          : ROUTES (subpath reverse proxy)"
  echo " Root Handling : $ROOT_MODE"
  [[ "$ROOT_MODE" == "redirect" ]] && echo " Root Target   : $ROOT_TARGET"
  [[ "$ROOT_MODE" == "proxy" ]] && echo " Root Backend  : $ROOT_BACKEND"
else
  echo " Mode          : LOAD BALANCER"
  echo " Backends      : $BACKENDS"
fi
echo " SSL Mode      : $SSL_TYPE"
echo " Nginx Config  : $NGINX_CONF"
echo " Logs Dir      : $LOG_DIR"
echo "--------------------------------------------------"

# ====================
# SAVE SUMMARY
# ====================

HOME_DIR="/home/$USER"
SUMMARY_FILE="$HOME_DIR/.summary.md"

PROXY_MODE="Load Balancer"
PROXY_TARGET="$BACKENDS"
if [[ -n "$ROUTES" ]]; then
  PROXY_MODE="Routes (subpath)"
  PROXY_TARGET="$ROUTES"
fi

cat > "$SUMMARY_FILE" <<EOF
# $DOMAIN

Created: $(date +'%Y-%m-%d %H:%M:%S')
Type: Reverse Proxy ($PROXY_MODE)

## Server

| Key | Value |
|-----|-------|
| Domain | $DOMAIN |
| User | $USER |
| Mode | $PROXY_MODE |
| Backends/Routes | $PROXY_TARGET |
| SSL | $SSL_TYPE |
| Nginx Conf | $NGINX_CONF |
| Logs | $LOG_DIR |
EOF

if [[ -n "$ROUTES" ]]; then
cat >> "$SUMMARY_FILE" <<EOF

## Root Handling

| Key | Value |
|-----|-------|
| Mode | $ROOT_MODE |
| Target | ${ROOT_TARGET:-—} |
| Backend | ${ROOT_BACKEND:-—} |
EOF
fi

chmod 600 "$SUMMARY_FILE"
chown "$USER:$USER" "$SUMMARY_FILE"
log "[✓] Summary saved → $SUMMARY_FILE"
