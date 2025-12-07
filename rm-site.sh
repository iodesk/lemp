#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/rm_wp_site.log"
MYSQL_ROOT_PASSWORD=$(cat /root/.mysql_root_password)
FILEGATOR_DIR="/usr/share/filegator"

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
generate_user_from_domain() {
  local domain="$1"
  IFS='.' read -ra parts <<< "$domain"
  local num="${#parts[@]}"

  if [[ $num -eq 2 ]]; then
    echo "${parts[0]}"
  else
    local base="${parts[$num-3]}"
    local sub="${parts[0]}"
    echo "${base}-${sub}"
  fi
}

# =====================================
# Parse args
# =====================================
DOMAIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    *) echo "Unknown argument: $1"; usage ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

# =====================================
# Prepare vars
# =====================================
USER=$(generate_user_from_domain "$DOMAIN")
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
read -p "Type YES to confirm: " CONFIRM
[[ "$CONFIRM" != "YES" ]] && { echo "Cancelled."; exit 1; }

# =====================================
# Remove Nginx vhost
# =====================================
log "Removing NGINX config..."
rm -f "/etc/nginx/sites-available/${USER}-vhost.conf"
rm -f "/etc/nginx/sites-enabled/${USER}-vhost.conf"

# =====================================
# Remove PHP-FPM pool
# =====================================
log "Removing PHP-FPM pool..."
rm -f "/etc/php/$PHP_VERSION/fpm/pool.d/${USER}.conf"

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

OCACHE="$SITE_DIR/public_html/wp-content/object-cache.php"
if [[ -f "$OCACHE" ]]; then
  rm -f "$OCACHE"
  log "Removed: $OCACHE"
fi

if [[ -f "/var/spool/cron/$USER" ]]; then
  rm -f "/var/spool/cron/$USER"
  log "Removed cron jobs for: $USER"
fi

# =====================================
# Delete Redis db_user
# =====================================
PREFIX_PATTERN="${DOMAIN//./_}_*"
COUNT=$(redis-cli --scan --pattern "$PREFIX_PATTERN" | wc -l)

if [[ "$COUNT" -gt 0 ]]; then
  log "Removing Redis keys with prefix: $PREFIX_PATTERN"
  redis-cli --scan --pattern "$PREFIX_PATTERN" | xargs -r redis-cli del
  log "Redis keys removed: $COUNT"
else
  log "No Redis keys found for prefix: $PREFIX_PATTERN"
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

# =====================================
# Reload services safely
# =====================================
log "Reloading services..."
systemctl reload nginx || log "[i] nginx reload failed"
sleep 2
systemctl reload php$PHP_VERSION-fpm || log "[i] php-fpm reload failed"

# =====================================
# Done
# =====================================
log "✅ Site $DOMAIN removed cleanly & safely."
