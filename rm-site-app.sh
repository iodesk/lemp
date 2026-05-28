#!/usr/bin/env bash
set -e

LOG_FILE="/var/log/rm_wp_site.log"
MYSQL_ROOT_PASSWORD=$(cat /root/.mysql_root_password)

: > "$LOG_FILE"

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

usage() {
  echo "Usage: $0 -d domain.com"
  exit 1
}

# =====================================
# Convert domain → username
# =====================================
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

# =====================================
# Parse args
# =====================================
DOMAIN=""
FORCE="no"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -y|--yes) FORCE="yes"; shift ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

# =====================================
# Prepare vars
# =====================================
USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN"
PHP_VERSION_FILE="$USER_HOME/.php_version"
DB_NAME="$USER"
DB_USER="$USER"

if [[ ! -f "$PHP_VERSION_FILE" ]]; then
  log "[x] PHP version file missing: $PHP_VERSION_FILE"
  exit 1
fi
PHP_VERSION=$(cat "$PHP_VERSION_FILE")

if [[ ! -d "$USER_HOME" ]]; then
  log "[x] User home dir not found: $USER_HOME"
  exit 1
fi

if [[ ! "$SITE_DIR" =~ ^/home/$USER/ ]]; then
  log "[x] Abort: SITE_DIR is unsafe path"
  exit 1
fi

# =====================================
# Confirm
# =====================================
echo "WARNING: This will DELETE site:"
echo "Domain      : $DOMAIN"
echo "User        : $USER"
echo "Site Dir    : $SITE_DIR"
echo "DB          : $DB_NAME"

if [[ "$FORCE" != "yes" ]]; then
  read -p "Type YES to confirm: " CONFIRM </dev/tty
  [[ "$CONFIRM" != "YES" ]] && { echo "Cancelled."; exit 1; }
fi

# =====================================
# Remove Nginx vhost
# =====================================
log "Removing NGINX config..."
rm -f "/etc/nginx/sites-available/$DOMAIN.conf"
rm -f "/etc/nginx/sites-enabled/$DOMAIN.conf"

# =====================================
# Remove PHP-FPM pool
# =====================================
log "Removing PHP-FPM pool..."
rm -f "/etc/php/$PHP_VERSION/fpm/pool.d/$DOMAIN.conf"

# =====================================
# Remove Let’s Encrypt + dummy SSL
# =====================================
log "Removing SSL certificates..."

rm -rf "/etc/letsencrypt/live/$DOMAIN"
rm -rf "/etc/letsencrypt/archive/$DOMAIN"
rm -f "/etc/letsencrypt/renewal/$DOMAIN.conf"

rm -f "/etc/ssl/selfsigned/$DOMAIN.crt"
rm -f "/etc/ssl/selfsigned/$DOMAIN.key"

# =====================================
# Delete site files safely
# =====================================
log "Removing site directory: $SITE_DIR"
rm -rf "$SITE_DIR"

# =====================================
# Remove user logs
# =====================================
rm -rf "$USER_HOME/logs"

LOGROTATE_FILE="/etc/logrotate.d/$USER.conf"
if [[ -f "$LOGROTATE_FILE" ]]; then
  log "Removing logrotate config: $LOGROTATE_FILE"
  rm -f "$LOGROTATE_FILE"
fi

if [[ -d "$USER_HOME/.wp-cli" ]]; then
  rm -rf "$USER_HOME/.wp-cli"
  log "Removed: $USER_HOME/.wp-cli"
fi

if [[ -d "$USER_HOME/tmp" ]]; then
  rm -rf "$USER_HOME/tmp"
  log "Removed: $USER_HOME/tmp"
fi

if [[ -f "/var/spool/cron/$USER" ]]; then
  rm -f "/var/spool/cron/$USER"
  log "Removed cron jobs for: $USER"
fi

# =====================================
# Delete Redis keys
# =====================================
if command -v redis-cli >/dev/null 2>&1 && redis-cli ping >/dev/null 2>&1; then
  PREFIX_PATTERN="${DOMAIN//./_}_*"
  COUNT=$(redis-cli --scan --pattern "$PREFIX_PATTERN" | wc -l)

  if [[ "$COUNT" -gt 0 ]]; then
    log "Removing Redis keys with prefix: $PREFIX_PATTERN"
    redis-cli --scan --pattern "$PREFIX_PATTERN" | xargs -r redis-cli del
    log "Redis keys removed: $COUNT"
  else
    log "No Redis keys found for prefix: $PREFIX_PATTERN"
  fi
else
  log "[i] Redis not available, skipping key cleanup"
fi

# =====================================
# Delete Linux user
# =====================================
if id "$USER" >/dev/null 2>&1; then
  log "Deleting system user: $USER"
  userdel -r "$USER" || log "[i] User $USER not fully deleted"
fi

# =====================================
# Delete database + user
# =====================================
log "Dropping DB: $DB_NAME"
mariadb -u root -p"$MYSQL_ROOT_PASSWORD" <<SQL
DROP DATABASE IF EXISTS \`$DB_NAME\`;
DROP USER IF EXISTS '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL

# =====================================
# Delete filemanager
# =====================================
FB_HOST="http://127.0.0.1:2222"
FB_TOKEN_FILE="/root/.filebrowser_token"

if [[ -f "$FB_TOKEN_FILE" ]]; then

  TOKEN=$(<"$FB_TOKEN_FILE")

  log "[FB] Fetching Filebrowser user list..."

  USER_LIST=$(curl -s -X GET "$FB_HOST/api/users" \
      -H "Content-Type: application/json" \
      -H "X-Auth: $TOKEN")

  if [[ -n "$USER_LIST" ]]; then

    log "[FB] Checking Filebrowser UID for: $USER"

    FB_UID=$(echo "$USER_LIST" | jq ".[] | select(.username==\"$USER\") | .id")

    if [[ -n "$FB_UID" ]]; then

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
      HTTP_CODE=$(echo "$HTTP_CODE" | tail -n1 | tr -dc '0-9')

      if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "201" || "$HTTP_CODE" == "204" ]]; then
        log "[FB] Filebrowser user '$USER' deleted"
      else
        log "[FB] ERROR deleting Filebrowser user (HTTP $HTTP_CODE)"
      fi
      rm -f "$FB_DEL_TMP"

    else
      log "[FB] User '$USER' not found in Filebrowser. Skipping."
    fi

  else
    log "[FB] ERROR: Could not fetch user list (empty response)"
  fi

else
  log "[FB] WARNING: Token file not found → $FB_TOKEN_FILE"
  log "[FB] Skipping Filebrowser user removal."
fi

# =====================================
# Reload services safely
# =====================================
log "Reloading services..."
nginx -t >> "$LOG_FILE" 2>&1 && systemctl reload nginx || log "[i] nginx reload failed"
sleep 1
systemctl reload php$PHP_VERSION-fpm || log "[i] php-fpm reload failed"

# =====================================
# Done
# =====================================
log "Site $DOMAIN removed cleanly & safely."
