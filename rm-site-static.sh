#!/usr/bin/env bash
set -e

# ====================
# CONFIG & FUNCTIONS
# ====================

LOG_FILE="/var/log/rm_static_site.log"
USER_NGINX="nginx"

: > "$LOG_FILE"

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

usage() {
  echo "Usage: rm-site-static.sh -d domain.com"
  exit 1
}

is_valid_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

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
# PARSE ARGUMENTS
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
is_valid_domain "$DOMAIN" || { echo "Invalid domain: $DOMAIN"; exit 1; }

# ====================
# SETUP VARS
# ====================

USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
USER_HOME="/home/$USER"

NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
LOGROTATE_FILE="/etc/logrotate.d/$USER.conf"

SSL_SELF_DIR="/etc/ssl/selfsigned"
SSL_SELF_CERT="$SSL_SELF_DIR/$DOMAIN.crt"
SSL_SELF_KEY="$SSL_SELF_DIR/$DOMAIN.key"

LE_LIVE="/etc/letsencrypt/live/$DOMAIN"
LE_ARCHIVE="/etc/letsencrypt/archive/$DOMAIN"
LE_RENEW="/etc/letsencrypt/renewal/$DOMAIN.conf"

# ====================
# CONFIRMATION
# ====================
echo "WARNING: This will FULLY DELETE the static site:"
echo "Domain:      $DOMAIN"
echo "User:        $USER"
echo "Home Dir:    $USER_HOME"
echo "--------------------------------------------"

if [[ "$FORCE" != "yes" ]]; then
  read -p "Type YES to confirm: " CONFIRM </dev/tty
  [[ "$CONFIRM" != "YES" ]] && { echo "Cancelled."; exit 1; }
fi

log "===== START REMOVING STATIC SITE: $DOMAIN ====="

# ====================
# REMOVE NGINX CONFIG
# ====================
log "Removing Nginx configuration..."
rm -f "$NGINX_LINK"
rm -f "$NGINX_CONF"

# ====================
# REMOVE SSL (SELF-SIGNED / DUMMY)
# ====================
log "Removing self-signed/dummy SSL..."
rm -f "$SSL_SELF_CERT" "$SSL_SELF_KEY"

# ====================
# REMOVE SSL (LET'S ENCRYPT)
# ====================
log "Removing Let's Encrypt certificates..."
rm -rf "$LE_LIVE" "$LE_ARCHIVE"
rm -f "$LE_RENEW"

# ====================
# REMOVE LOGROTATE
# ====================
if [[ -f "$LOGROTATE_FILE" ]]; then
  log "Removing logrotate config..."
  rm -f "$LOGROTATE_FILE"
fi

# ====================
# REMOVE FILEBROWSER USER
# ====================
FB_HOST="http://127.0.0.1:2222"
FB_TOKEN_FILE="/root/.filebrowser_token"

if [[ -f "$FB_TOKEN_FILE" ]]; then
  TOKEN=$(cat "$FB_TOKEN_FILE")
  log "[FB] Checking Filebrowser user: $USER"
  
  USER_LIST=$(curl -s -X GET "$FB_HOST/api/users" \
      -H "Content-Type: application/json" \
      -H "X-Auth: $TOKEN")

  if [[ -n "$USER_LIST" ]]; then
    FB_UID=$(echo "$USER_LIST" | jq -r ".[] | select(.username==\"$USER\") | .id" 2>/dev/null)
    
    if [[ -n "$FB_UID" && "$FB_UID" != "null" ]]; then
      log "[FB] Found UID = $FB_UID → removing..."

      FB_ADMIN_PASS=""
      if [[ -f /root/.filebrowser_admin ]]; then
        FB_ADMIN_PASS=$(jq -r '.password' /root/.filebrowser_admin)
      fi

      FB_DEL_TMP="/tmp/fb-del-$USER.json"
      jq -nc --argjson uid "$FB_UID" --arg adminpass "$FB_ADMIN_PASS" \
        '{what:"user",which:[$uid],current_password:$adminpass}' > "$FB_DEL_TMP"

      HTTP_CODE=$(curl -s -w "%{http_code}" -o /dev/null \
          -X DELETE "$FB_HOST/api/users/$FB_UID" \
          -H "X-Auth: $TOKEN" \
          -H "Content-Type: application/json" \
          -d @"$FB_DEL_TMP")
      HTTP_CODE=$(echo "$HTTP_CODE" | tr -dc '0-9')

      if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" || "$HTTP_CODE" == "204" ]]; then
        log "[FB] User '$USER' deleted from Filebrowser"
      else
        log "[FB] ERROR deleting Filebrowser user (HTTP $HTTP_CODE)"
      fi
      rm -f "$FB_DEL_TMP"
    else
      log "[FB] User '$USER' not found in Filebrowser"
    fi
  else
    log "[FB] ERROR: Could not fetch Filebrowser user list"
  fi
else
  log "[FB] WARNING: Token file not found → $FB_TOKEN_FILE. Skipping."
fi

# ====================
# REMOVE LINUX USER & HOME
# ====================
if id "$USER" &>/dev/null; then
  log "Removing Linux user and home directory: $USER"
  userdel -r "$USER" 2>/dev/null || {
    log "[!] userdel -r failed, manual cleanup of $USER_HOME..."
    rm -rf "$USER_HOME"
    userdel "$USER"
  }
else
  log "User $USER not found in system, ensuring home directory is gone..."
  rm -rf "$USER_HOME"
fi

# ====================
# RELOAD NGINX
# ====================
log "Reloading Nginx..."
nginx -t &>/dev/null && systemctl reload nginx || log "[x] Nginx reload failed (config may be invalid)"

# ====================
# DONE
# ====================
log "[✓] Static site $DOMAIN removed successfully"
echo "--------------------------------------------"
echo " FULL CLEAN REMOVAL COMPLETED"
echo " Site: $DOMAIN"
echo " User: $USER"
echo "--------------------------------------------"
