#!/usr/bin/env bash
set -e

LOG_FILE="/var/log/rm_wp_site.log"
MYSQL_ROOT_PASSWORD=$(cat /root/.mysql_root_password)

: > "$LOG_FILE"

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

usage() {
  echo "Usage: $0 -d domain.com [-u username] [-y]"
  echo ""
  echo "Options:"
  echo "  -d, --domain   Domain to remove (required)"
  echo "  -u, --user     Owner username (auto-detected if omitted)"
  echo "  -y, --yes      Skip confirmation prompt"
  exit 1
}

# =====================================
# Parse args
# =====================================
DOMAIN=""
USER=""
FORCE="no"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -u|--user) USER="$2"; shift 2 ;;
    -y|--yes) FORCE="yes"; shift ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

# =====================================
# Auto-detect user from domain directory
# =====================================
if [[ -z "$USER" ]]; then
  FOUND_PATH=$(find /home -maxdepth 2 -type d -name "$DOMAIN" 2>/dev/null | head -1)

  if [[ -n "$FOUND_PATH" ]]; then
    USER=$(echo "$FOUND_PATH" | cut -d'/' -f3)
    log "[i] Auto-detected user: $USER (from $FOUND_PATH)"
  else
    echo "[x] Could not auto-detect user for domain: $DOMAIN"
    echo "    Use -u <username> to specify manually."
    exit 1
  fi
fi

# =====================================
# Prepare vars
# =====================================
USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN"
PHP_VERSION_FILE="$USER_HOME/.php_version"
DB_NAME="$(echo "${DOMAIN//[.-]/_}" | cut -c1-64)"
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

if [[ ! -d "$SITE_DIR" ]]; then
  log "[x] Site directory not found: $SITE_DIR"
  exit 1
fi

if [[ ! "$SITE_DIR" =~ ^/home/$USER/ ]]; then
  log "[x] Abort: SITE_DIR is unsafe path"
  exit 1
fi

# =====================================
# Detect other domains under same user
# =====================================
OTHER_DOMAINS=()
for dir in "$USER_HOME"/*/public_html; do
  [[ -d "$dir" ]] || continue
  d=$(basename "$(dirname "$dir")")
  [[ "$d" == "$DOMAIN" ]] && continue
  [[ "$d" =~ \. ]] && OTHER_DOMAINS+=("$d")
done

HAS_OTHER_DOMAINS=false
if [[ ${#OTHER_DOMAINS[@]} -gt 0 ]]; then
  HAS_OTHER_DOMAINS=true
fi

# =====================================
# Confirm
# =====================================
echo ""
echo "═══════════════════════════════════════════"
echo " REMOVE SITE: $DOMAIN"
echo "═══════════════════════════════════════════"
echo ""
echo "  Domain      : $DOMAIN"
echo "  User        : $USER"
echo "  Site Dir    : $SITE_DIR"
echo "  DB          : $DB_NAME"
echo ""

if [[ "$HAS_OTHER_DOMAINS" == true ]]; then
  echo "  ⚠ User '$USER' has other domains:"
  for od in "${OTHER_DOMAINS[@]}"; do
    echo "    • $od"
  done
  echo ""
  echo "  → Will KEEP user, FPM pool, and Filebrowser account"
  echo "  → Will ONLY remove this domain's files, vhost, DB, and logs"
else
  echo "  → Will REMOVE everything: user, FPM pool, FM account, all data"
fi

echo ""

if [[ "$FORCE" != "yes" ]]; then
  read -p "Type YES to confirm: " CONFIRM </dev/tty
  [[ "$CONFIRM" != "YES" ]] && { echo "Cancelled."; exit 1; }
fi

echo ""
log "Starting removal of $DOMAIN (user: $USER, other_domains: $HAS_OTHER_DOMAINS)"

# =====================================
# Remove Nginx vhost
# =====================================
log "Removing NGINX config..."
rm -f "/etc/nginx/sites-available/$DOMAIN.conf"
rm -f "/etc/nginx/sites-enabled/$DOMAIN.conf"

# =====================================
# Remove SSL certificates
# =====================================
log "Removing SSL certificates..."
rm -rf "/etc/letsencrypt/live/$DOMAIN"
rm -rf "/etc/letsencrypt/archive/$DOMAIN"
rm -f "/etc/letsencrypt/renewal/$DOMAIN.conf"
rm -f "/etc/ssl/selfsigned/$DOMAIN.crt"
rm -f "/etc/ssl/selfsigned/$DOMAIN.key"

# =====================================
# Remove site directory
# =====================================
log "Removing site directory: $SITE_DIR"
rm -rf "$SITE_DIR"

# =====================================
# Remove domain-specific logs
# =====================================
log "Removing domain logs: $USER_HOME/logs/$DOMAIN/"
rm -rf "$USER_HOME/logs/$DOMAIN"

if [[ "$HAS_OTHER_DOMAINS" == false ]]; then
  rm -rf "$USER_HOME/logs"
fi

# =====================================
# Remove summary file for this domain
# =====================================
rm -f "$USER_HOME/.summary-$DOMAIN.md"
rm -f "$USER_HOME/.summary.md" 2>/dev/null || true

# =====================================
# Delete Redis keys for this domain
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
# Delete database (per-domain)
# =====================================
log "Dropping DB: $DB_NAME"
mariadb -u root -p"$MYSQL_ROOT_PASSWORD" <<SQL
DROP DATABASE IF EXISTS \`$DB_NAME\`;
SQL

if [[ "$HAS_OTHER_DOMAINS" == false ]]; then
  log "Dropping DB user: $DB_USER"
  mariadb -u root -p"$MYSQL_ROOT_PASSWORD" <<SQL
DROP USER IF EXISTS '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL
else
  log "Revoking privileges on $DB_NAME for user $DB_USER"
  mariadb -u root -p"$MYSQL_ROOT_PASSWORD" <<SQL
REVOKE ALL PRIVILEGES ON \`$DB_NAME\`.* FROM '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL
fi

# =====================================
# Conditional: Remove user-level resources
# =====================================
if [[ "$HAS_OTHER_DOMAINS" == false ]]; then

  log "Removing PHP-FPM pool for user $USER..."
  rm -f "/etc/php/$PHP_VERSION/fpm/pool.d/$USER.conf"
  rm -f "/etc/php/$PHP_VERSION/fpm/pool.d/$DOMAIN.conf"

  LOGROTATE_FILE="/etc/logrotate.d/$USER.conf"
  if [[ -f "$LOGROTATE_FILE" ]]; then
    log "Removing logrotate config: $LOGROTATE_FILE"
    rm -f "$LOGROTATE_FILE"
  fi

  rm -rf "$USER_HOME/.wp-cli" 2>/dev/null || true
  rm -rf "$USER_HOME/tmp" 2>/dev/null || true
  rm -f "/var/spool/cron/$USER" 2>/dev/null || true

  FB_HOST="http://127.0.0.1:2222"
  FB_TOKEN_FILE="/root/.filebrowser_token"

  if [[ -f "$FB_TOKEN_FILE" ]]; then
    TOKEN=$(<"$FB_TOKEN_FILE")

    USER_LIST=$(curl -s -X GET "$FB_HOST/api/users" \
        -H "Content-Type: application/json" \
        -H "X-Auth: $TOKEN")

    if [[ -n "$USER_LIST" ]]; then
      FB_UID=$(echo "$USER_LIST" | jq ".[] | select(.username==\"$USER\") | .id")

      if [[ -n "$FB_UID" ]]; then
        log "[FB] Removing Filebrowser user '$USER' (UID=$FB_UID)..."

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
          log "[FB] Filebrowser user deleted"
        else
          log "[FB] ERROR deleting user (HTTP $HTTP_CODE)"
        fi
        rm -f "$FB_DEL_TMP"
      else
        log "[FB] User not found in Filebrowser"
      fi
    fi
  else
    log "[FB] Token file not found, skipping"
  fi

  if id "$USER" >/dev/null 2>&1; then
    log "Deleting system user: $USER"
    userdel -r "$USER" || log "[i] User $USER not fully deleted (some files may remain)"
  fi

else
  log "[i] Keeping user '$USER' — still has domains: ${OTHER_DOMAINS[*]}"
fi

# =====================================
# Reload services
# =====================================
log "Reloading services..."
nginx -t >> "$LOG_FILE" 2>&1 && systemctl reload nginx || log "[i] nginx reload failed"
sleep 1
systemctl reload php$PHP_VERSION-fpm || log "[i] php-fpm reload failed"

# =====================================
# Done
# =====================================
echo ""
echo "═══════════════════════════════════════════"
if [[ "$HAS_OTHER_DOMAINS" == true ]]; then
  log "Domain $DOMAIN removed. User '$USER' kept (has other domains)."
  echo " Domain $DOMAIN removed"
  echo " User '$USER' still active with:"
  for od in "${OTHER_DOMAINS[@]}"; do
    echo "   • $od"
  done
else
  log "Site $DOMAIN and user $USER fully removed."
  echo "Site $DOMAIN fully removed (user + all data)"
fi
echo "═══════════════════════════════════════════"
echo ""
