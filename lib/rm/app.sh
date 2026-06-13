#!/usr/bin/env bash
set -e

LOG_FILE="$LOG_DIR/rm_wp_site.log"

DOMAIN=""
USER=""
FORCE="no"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -u|--user) USER="$2"; shift 2 ;;
    -y|--yes) FORCE="yes"; shift ;;
    *) echo "[x] Unknown arg: $1"; exit 1 ;;
  esac
done

validate_domain "$DOMAIN"

if [[ -z "$USER" ]]; then
  FOUND_PATH=$(find /home -maxdepth 2 -type d -name "$DOMAIN" 2>/dev/null | head -1)

  if [[ -n "$FOUND_PATH" ]]; then
    USER=$(echo "$FOUND_PATH" | cut -d'/' -f3)
    log "[i] Auto-detected user: $USER (from $FOUND_PATH)"
  else
    USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
    log "[i] Fallback user from domain: $USER"
  fi
fi

USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN"
PHP_VERSION_DOMAIN_FILE="$USER_HOME/.php_version_$DOMAIN"
PHP_VERSION_FILE="$USER_HOME/.php_version"

if [[ -f "$PHP_VERSION_DOMAIN_FILE" ]]; then
  PHP_VERSION=$(cat "$PHP_VERSION_DOMAIN_FILE")
elif [[ -f "$PHP_VERSION_FILE" ]]; then
  PHP_VERSION=$(cat "$PHP_VERSION_FILE")
else
  log "[x] PHP version file missing for domain $DOMAIN"
  exit 1
fi

if [[ ! -d "$USER_HOME" ]]; then
  log "[x] User home dir not found: $USER_HOME"
  exit 1
fi

if [[ ! "$SITE_DIR" =~ ^/home/$USER/ ]]; then
  log "[x] Abort: SITE_DIR is unsafe path"
  exit 1
fi

OTHER_DOMAINS=()
if detect_other_domains "$USER" "$DOMAIN" > /dev/null 2>&1; then
  mapfile -t OTHER_DOMAINS < <(detect_other_domains "$USER" "$DOMAIN")
fi

HAS_OTHER_DOMAINS=false
if [[ ${#OTHER_DOMAINS[@]} -gt 0 ]]; then
  HAS_OTHER_DOMAINS=true
fi

DB_NAME="$(echo "${DOMAIN//[.-]/_}" | cut -c1-64)"
DB_USER="$(echo "${DOMAIN//[.-]/_}" | cut -c1-32)"

FPM_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/$DOMAIN.conf"

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
  echo "  → Will KEEP user and Filebrowser account"
  echo "  → Will remove this domain's pool, files, vhost, DB, and logs"
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

log "Removing NGINX config..."
rm -f "/etc/nginx/sites-available/$DOMAIN.conf"
rm -f "/etc/nginx/sites-enabled/$DOMAIN.conf"

remove_ssl "$DOMAIN"

log "Removing site directory: $SITE_DIR"
rm -rf "$SITE_DIR"

log "Removing domain logs: $USER_HOME/logs/$DOMAIN/"
rm -rf "$USER_HOME/logs/$DOMAIN"

if [[ "$HAS_OTHER_DOMAINS" == false ]]; then
  rm -rf "$USER_HOME/logs"
fi

rm -f "$USER_HOME/.summary-$DOMAIN.md"
rm -f "$USER_HOME/.summary.md" 2>/dev/null || true

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

check_mysql_root_password
MYSQL_ROOT_PASSWORD=$(< "$MYSQL_PASS_FILE")

log "Dropping DB: $DB_NAME (user: $DB_USER)"

mariadb -u root -p"$MYSQL_ROOT_PASSWORD" <<SQL
DROP DATABASE IF EXISTS \`$DB_NAME\`;
DROP USER IF EXISTS '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
SQL

log "Removing PHP-FPM pool: $FPM_CONF"
rm -f "$FPM_CONF"
rm -f "$USER_HOME/.php_version_$DOMAIN"

if [[ "$HAS_OTHER_DOMAINS" == false ]]; then

  LOGROTATE_FILE="/etc/logrotate.d/$USER.conf"
  if [[ -f "$LOGROTATE_FILE" ]]; then
    log "Removing logrotate config: $LOGROTATE_FILE"
    rm -f "$LOGROTATE_FILE"
  fi

  rm -rf "$USER_HOME/.wp-cli" 2>/dev/null || true
  rm -rf "$USER_HOME/tmp" 2>/dev/null || true
  rm -f "/var/spool/cron/$USER" 2>/dev/null || true

  remove_fb_user "$USER" || true

  if id "$USER" >/dev/null 2>&1; then
    log "Deleting system user: $USER"
    userdel -r "$USER" || log "[i] User $USER not fully deleted (some files may remain)"
  fi

else
  log "[i] Keeping user '$USER' — still has domains: ${OTHER_DOMAINS[*]}"
fi

log "Reloading services..."
nginx -t >> "$LOG_FILE" 2>&1 && systemctl reload nginx || log "[i] nginx reload failed"
sleep 1
systemctl reload php$PHP_VERSION-fpm || log "[i] php-fpm reload failed"

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
