#!/usr/bin/env bash
set -e

LOG_FILE="/var/log/remove_proxy_site.log"

: > "$LOG_FILE"

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

usage() {
  echo "Usage: rm-site-proxy.sh -d domain.com"
  exit 1
}

# ====================
# ARG PARSE
# ====================
DOMAIN=""
FORCE="no"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -y|--yes) FORCE="yes"; shift ;;
    *) usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

# ====================
# DOMAIN → USER
# ====================
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

USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
NGINX_AVAIL="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN.conf"
HOME_DIR="/home/$USER"
LOG_DIR="$HOME_DIR/logs/nginx"

SSL_SELF_DIR="/etc/ssl/selfsigned"
SSL_SELF_CERT="$SSL_SELF_DIR/$DOMAIN.crt"
SSL_SELF_KEY="$SSL_SELF_DIR/$DOMAIN.key"

LE_LIVE="/etc/letsencrypt/live/$DOMAIN"
LE_ARCHIVE="/etc/letsencrypt/archive/$DOMAIN"
LE_RENEW="/etc/letsencrypt/renewal/$DOMAIN.conf"

# ====================
# PREFLIGHT CHECK (STOP IF NOTHING EXISTS)
# ====================
FOUND=0

[[ -e "$NGINX_ENABLED" ]] && FOUND=1
[[ -e "$NGINX_AVAIL"   ]] && FOUND=1
[[ -e "$SSL_SELF_CERT" ]] && FOUND=1
[[ -d "$LE_LIVE"       ]] && FOUND=1
id "$USER" &>/dev/null && FOUND=1

if [[ $FOUND -eq 0 ]]; then
  log "Nothing to remove!"
  exit 1
fi

log "===== FULL CLEAN REMOVAL START ====="
log "Domain : $DOMAIN"
log "User   : $USER"

# ====================
# REMOVE NGINX VHOST
# ====================
rm -f "$NGINX_ENABLED"
rm -f "$NGINX_AVAIL"
log "Nginx vhost removed"

# ====================
# RELOAD NGINX
# ====================
if nginx -t; then
  systemctl reload nginx
  log "Nginx reloaded"
else
  log "ERROR: nginx config broken after vhost removal"
  exit 1
fi

# ====================
# REMOVE SSL (SELF)
# ====================
rm -f "$SSL_SELF_CERT" "$SSL_SELF_KEY" || true
log "Self-signed SSL removed"

# ====================
# REMOVE SSL (LETS ENCRYPT)
# ====================
rm -rf "$LE_LIVE" "$LE_ARCHIVE" || true
rm -f "$LE_RENEW" || true
log "Let's Encrypt SSL removed"

# ====================
# REMOVE USER + HOME
# ====================
if id "$USER" &>/dev/null; then
  userdel -r "$USER" || true
  log "Linux user removed"
fi

rm -rf "$HOME_DIR" || true
log "Home directory removed"

# ====================
# FINAL SUMMARY
# ====================
echo "--------------------------------------------------"
echo " FULL CLEAN REMOVAL COMPLETED"
echo "--------------------------------------------------"
echo " Domain          : $DOMAIN"
echo " User            : $USER"
echo " Nginx vhost     : REMOVED"
echo " SSL (self)      : REMOVED"
echo " SSL (LE)        : REMOVED"
echo " User + /home    : REMOVED"
echo "--------------------------------------------------"
