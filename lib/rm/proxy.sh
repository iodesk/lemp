#!/usr/bin/env bash
set -e

LOG_FILE="$LOG_DIR/rm_proxy_site.log"

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

NGINX_AVAIL="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_ENABLED="/etc/nginx/sites-enabled/$DOMAIN.conf"
HOME_DIR="/home/$USER"

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
echo " REMOVE PROXY SITE: $DOMAIN"
echo "═══════════════════════════════════════════"
echo ""
echo "  Domain      : $DOMAIN"
echo "  User        : $USER"
echo ""

if [[ "$HAS_OTHER_DOMAINS" == true ]]; then
  echo "  ⚠ User '$USER' has other domains:"
  for od in "${OTHER_DOMAINS[@]}"; do
    echo "    • $od"
  done
  echo ""
  echo "  → Will KEEP user"
  echo "  → Will remove this domain's vhost, SSL, and site dir"
else
  echo "  → Will REMOVE everything: user, vhost, SSL, home dir"
fi

echo ""

if [[ "$FORCE" != "yes" ]]; then
  read -p "Type YES to confirm: " CONFIRM </dev/tty
  [[ "$CONFIRM" != "YES" ]] && { echo "Cancelled."; exit 1; }
fi

log "===== REMOVAL START ====="
log "Domain : $DOMAIN"
log "User   : $USER"

rm -f "$NGINX_ENABLED"
rm -f "$NGINX_AVAIL"
log "Nginx vhost removed"

if nginx -t; then
  systemctl reload nginx
  log "Nginx reloaded"
else
  log "ERROR: nginx config broken after vhost removal"
  exit 1
fi

remove_ssl "$DOMAIN"

log "Removing site directory: $HOME_DIR/$DOMAIN"
rm -rf "$HOME_DIR/$DOMAIN"

log "Removing domain logs: $HOME_DIR/logs/$DOMAIN/"
rm -rf "$HOME_DIR/logs/$DOMAIN"
rm -f "$HOME_DIR/.summary-$DOMAIN.md"

if [[ "$HAS_OTHER_DOMAINS" == false ]]; then
  rm -rf "$HOME_DIR/logs"

  LOGROTATE_FILE="/etc/logrotate.d/$USER.conf"
  [[ -f "$LOGROTATE_FILE" ]] && rm -f "$LOGROTATE_FILE"

  remove_fb_user "$USER" || true

  if id "$USER" &>/dev/null; then
    log "Deleting system user: $USER"
    userdel -r "$USER" || log "[i] User $USER not fully deleted"
  fi
  rm -rf "$HOME_DIR" || true
else
  log "[i] Keeping user '$USER' — still has domains: ${OTHER_DOMAINS[*]}"
fi

echo ""
echo "═══════════════════════════════════════════"
if [[ "$HAS_OTHER_DOMAINS" == true ]]; then
  log "Proxy $DOMAIN removed. User '$USER' kept."
  echo " Proxy $DOMAIN removed"
  echo " User '$USER' still active with:"
  for od in "${OTHER_DOMAINS[@]}"; do
    echo "   • $od"
  done
else
  log "Proxy site $DOMAIN and user $USER fully removed."
  echo " Proxy site $DOMAIN fully removed (user + all data)"
fi
echo "═══════════════════════════════════════════"
echo ""
