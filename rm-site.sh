#!/usr/bin/env bash
set -e

# ====================
# CONFIG
# ====================

REMOTE_BASE="https://vps.fio.link"

usage() {
  echo "Usage: rm-site.sh -d domain.com"
  exit 1
}

is_valid_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

# ====================
# PARSE ARGS
# ====================

DOMAIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage
is_valid_domain "$DOMAIN" || { echo "Invalid domain"; exit 1; }

# ====================
# DETECTION + REMOTE EXEC
# ====================

NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"

if [[ ! -f "$NGINX_CONF" ]]; then
  echo "[x] ERROR: No Nginx configuration found for $DOMAIN"
  echo "    Checked path: $NGINX_CONF"
  exit 1
fi

if grep -q "proxy_pass" "$NGINX_CONF"; then
  MODE="Reverse Proxy"
  SCRIPT="rm-site-proxy.sh"
elif grep -q "fastcgi_pass" "$NGINX_CONF"; then
  MODE="PHP App"
  SCRIPT="rm-site-app.sh"
else
  MODE="Static Site"
  SCRIPT="rm-site-static.sh"
fi

log_info() {
  echo "[i] $1"
}

log_info "Detected: $MODE ($DOMAIN)"

echo ""
echo "WARNING: This will DELETE site: $DOMAIN"
echo "Type YES to confirm:"
read -r CONFIRM </dev/tty
[[ "$CONFIRM" != "YES" ]] && { echo "Cancelled."; exit 1; }

log_info "Routing to $SCRIPT..."

exec bash <(curl -fsSL "$REMOTE_BASE/$SCRIPT") -d "$DOMAIN" -y
