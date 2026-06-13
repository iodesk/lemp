#!/usr/bin/env bash
set -e

LOG_FILE="$LOG_DIR/add_proxy_site.log"

DOMAIN=""
BACKENDS=""
ROUTES=""
SSL_TYPE="none"
ROOT_MODE="403"
ROOT_TARGET=""
ROOT_BACKEND=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -backends) BACKENDS="$2"; shift 2 ;;
    -routes) ROUTES="$2"; shift 2 ;;
    -ssl) SSL_TYPE="${2,,}"; shift 2 ;;
    -root-mode) ROOT_MODE="$2"; shift 2 ;;
    -root-target) ROOT_TARGET="$2"; shift 2 ;;
    -root-backend) ROOT_BACKEND="$2"; shift 2 ;;
    *) echo "[x] Unknown arg: $1"; exit 1 ;;
  esac
done

validate_domain "$DOMAIN"
[[ -z "$ROUTES" && -z "$BACKENDS" ]] && BACKENDS="127.0.0.1:8080"

USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
UPSTREAM="${DOMAIN}_upstream"
VHOST_TEMPLATE="$FSS_CONF/nginx/proxy-vhost.conf"

if [[ -f "$NGINX_CONF" ]]; then
  log "[x] Nginx vhost already exists: $NGINX_CONF"
  exit 1
fi

if ! id "$USER" &>/dev/null; then
  useradd -m "$USER" || true
  log "Created user $USER"
else
  log "User exists: $USER"
fi

mkdir -p "/home/$USER/$DOMAIN"
mkdir -p "/home/$USER/logs/$DOMAIN/nginx"
chown "$USER:$USER" "/home/$USER"
chown -R "$USER:$USER" "/home/$USER/$DOMAIN" "/home/$USER/logs/$DOMAIN"

log "Configuring proxy vhost from template..."
cp "$VHOST_TEMPLATE" "$NGINX_CONF"

UPSTREAM_BLOCK=$(mktemp)
ROOT_BLOCK=$(mktemp)
ROUTES_BLOCK=$(mktemp)
DEFAULT_BLOCK=$(mktemp)
HEALTHZ_BLOCK=$(mktemp)
trap 'rm -f "$UPSTREAM_BLOCK" "$ROOT_BLOCK" "$ROUTES_BLOCK" "$DEFAULT_BLOCK" "$HEALTHZ_BLOCK"' EXIT
printf "map \$http_upgrade \$connection_upgrade { default upgrade; '' close; }\n" > "$UPSTREAM_BLOCK"

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

setup_ssl "$SSL_TYPE" "$DOMAIN" "$NGINX_CONF"

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
echo " Logs Dir      : /home/$USER/logs/$DOMAIN/nginx"
echo "--------------------------------------------------"

HOME_DIR="/home/$USER"
SUMMARY_FILE="$HOME_DIR/.summary-$DOMAIN.md"

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
| Logs | /home/$USER/logs/$DOMAIN/nginx |
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
