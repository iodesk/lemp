#!/usr/bin/env bash
set -e

LOG_FILE="$LOG_DIR/rm_static_site.log"

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

echo ""
echo "═══════════════════════════════════════════"
echo " REMOVE STATIC SITE: $DOMAIN"
echo "═══════════════════════════════════════════"
echo ""
echo "  Domain      : $DOMAIN"
echo "  User        : $USER"
echo "  Site Dir    : $SITE_DIR"
echo ""

if [[ "$HAS_OTHER_DOMAINS" == true ]]; then
  echo "  ⚠ User '$USER' has other domains:"
  for od in "${OTHER_DOMAINS[@]}"; do
    echo "    • $od"
  done
  echo ""
  echo "  → Will KEEP user and Filebrowser account"
  echo "  → Will ONLY remove this domain's files, vhost, and logs"
else
  echo "  → Will REMOVE everything: user, FM account, all data"
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

if [[ "$HAS_OTHER_DOMAINS" == false ]]; then

  LOGROTATE_FILE="/etc/logrotate.d/$USER.conf"
  if [[ -f "$LOGROTATE_FILE" ]]; then
    log "Removing logrotate config: $LOGROTATE_FILE"
    rm -f "$LOGROTATE_FILE"
  fi

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

log "Reloading Nginx..."
nginx -t >> "$LOG_FILE" 2>&1 && systemctl reload nginx || log "[i] nginx reload failed"

echo ""
echo "═══════════════════════════════════════════"
if [[ "$HAS_OTHER_DOMAINS" == true ]]; then
  log "Domain $DOMAIN removed. User '$USER' kept (has other domains)."
  echo "Domain $DOMAIN removed"
  echo " User '$USER' still active with:"
  for od in "${OTHER_DOMAINS[@]}"; do
    echo "   • $od"
  done
else
  log "Static site $DOMAIN and user $USER fully removed."
  echo "Static site $DOMAIN fully removed (user + all data)"
fi
echo "═══════════════════════════════════════════"
echo ""
