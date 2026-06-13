#!/usr/bin/env bash
set -e

LOG_FILE="$LOG_DIR/add_static_site.log"

DOMAIN=""
SSL_TYPE="none"
HTTP3="off"
MODE="multi"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -ssl) SSL_TYPE="$2"; shift 2 ;;
    -http3) HTTP3="on"; shift ;;
    --mode) MODE="$2"; shift 2 ;;
    *) echo "[x] Unknown arg: $1"; exit 1 ;;
  esac
done

validate_domain "$DOMAIN"

CREATE_NEW_USER=true

if [[ "$MODE" == "single" ]]; then
  DEFAULT_USER="$(get_default_username "$DOMAIN")"

  echo ""
  echo "Domain: $DOMAIN (static)"
  echo ""
  echo "Assign to which user?"
  echo "  1) Create new user [$DEFAULT_USER]"
  echo "  2) Use existing user"
  echo ""
  read -rp "Choice [1]: " USER_CHOICE
  USER_CHOICE="${USER_CHOICE:-1}"

  if [[ "$USER_CHOICE" == "2" ]]; then
    CREATE_NEW_USER=false
    mapfile -t EXISTING_USERS < <(awk -F: '$3 >= 1000 && $1 != "nobody" && $1 != "nfsnobody" {print $1}' /etc/passwd)

    if [[ ${#EXISTING_USERS[@]} -eq 0 ]]; then
      echo "[x] No existing users found. Creating new user instead."
      CREATE_NEW_USER=true
    else
      echo ""
      echo "Available users:"
      for i in "${!EXISTING_USERS[@]}"; do
        echo "  $((i+1))) ${EXISTING_USERS[$i]}"
      done
      echo ""
      read -rp "Select user [1]: " USER_IDX
      USER_IDX="${USER_IDX:-1}"
      USER="${EXISTING_USERS[$((USER_IDX-1))]}"

      if [[ -z "$USER" ]]; then
        echo "[x] Invalid selection. Exiting."
        exit 1
      fi
      echo "[✓] Using existing user: $USER"
    fi
  fi

  if [[ "$CREATE_NEW_USER" == true ]]; then
    read -rp "Username [$DEFAULT_USER]: " INPUT_USER
    USER="${INPUT_USER:-$DEFAULT_USER}"
    USER="$(echo "$USER" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9]//g')"
    USER="${USER:0:32}"

    if id "$USER" &>/dev/null; then
      echo "[!] User '$USER' already exists. Switching to existing user mode."
      CREATE_NEW_USER=false
    fi
  fi
else
  USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
fi

USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN/public_html"
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"
VHOST_TEMPLATE="$FSS_CONF/nginx/custom-vhost-static.conf"

if [[ -f "$NGINX_CONF" ]]; then
  log "[x] Nginx vhost already exists: $NGINX_CONF"
  exit 1
fi

if [[ "$MODE" == "single" && "$CREATE_NEW_USER" == true ]]; then
  log "Creating user $USER..."
  useradd -m -d "$USER_HOME" -s /bin/bash "$USER"
elif [[ "$MODE" == "multi" ]]; then
  if ! id "$USER" &>/dev/null; then
    log "Creating user $USER..."
    useradd -m -d "$USER_HOME" -s /bin/bash "$USER"
  else
    log "User exists: $USER"
  fi
else
  log "Using existing user $USER"
fi

mkdir -p "$SITE_DIR"
mkdir -p "$USER_HOME/logs/$DOMAIN/nginx"

chown "$USER:$USER" "$USER_HOME"
chown -R "$USER:$USER" "$USER_HOME/$DOMAIN" "$USER_HOME/logs/$DOMAIN"
chmod 711 "$USER_HOME"
chmod 755 "$USER_HOME/$DOMAIN" "$SITE_DIR"

if [[ ! -f "$SITE_DIR/index.html" ]]; then
cat > "$SITE_DIR/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>$DOMAIN</title>
</head>
<body>
  <h1>$DOMAIN</h1>
  <p>Static site ready.</p>
</body>
</html>
EOF
chown "$USER:$USER" "$SITE_DIR/index.html"
fi

log "Configuring NGINX static vhost..."
cp "$VHOST_TEMPLATE" "$NGINX_CONF"

sed -i "s|\$DOMAIN|$DOMAIN|g; s|\$USER|$USER|g" "$NGINX_CONF"
sed -i "s|/home/$USER/logs/nginx/|/home/$USER/logs/$DOMAIN/nginx/|g" "$NGINX_CONF"

ln -sf "$NGINX_CONF" "$NGINX_LINK"

setup_ssl "$SSL_TYPE" "$DOMAIN" "$NGINX_CONF" "$HTTP3"

FB_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
FB_EXISTED=false
FB_RC=0
setup_fb_user "$USER" "$FB_PASS" || FB_RC=$?
[[ $FB_RC -eq 2 ]] && FB_EXISTED=true

setup_logrotate "$USER"

log "[✓] Static site $DOMAIN created successfully"

echo ""
echo "--------------------------------------------"
echo "Site:           http${SSL_TYPE:+s}://$DOMAIN"
echo "User:           $USER"
echo "Root Folder:    $SITE_DIR"
echo "Logs:           $USER_HOME/logs/$DOMAIN/nginx/"
echo "Nginx Conf:     $NGINX_CONF"
echo "File Manager:   $FB_HOST"
echo "FM Username:    $USER"
if [[ "$FB_EXISTED" == true ]]; then
  echo "FM Password:    (existing, unchanged)"
else
  echo "FM Password:    $FB_PASS"
fi
echo "--------------------------------------------"

SUMMARY_FILE="$USER_HOME/.summary-$DOMAIN.md"

cat > "$SUMMARY_FILE" <<EOF
# $DOMAIN

Created: $(date +'%Y-%m-%d %H:%M:%S')
Type: Static Site
User: $USER ($([ "$CREATE_NEW_USER" == true ] && echo "new" || echo "existing"))

## Server

| Key | Value |
|-----|-------|
| Domain | $DOMAIN |
| User | $USER |
| Root | $SITE_DIR |
| Logs | $USER_HOME/logs/$DOMAIN/nginx/ |
| SSL | ${SSL_TYPE:-none} |

## File Manager

| Key | Value |
|-----|-------|
| URL | https://$DOMAIN/fm |
| Username | $USER |
| Password | $([ "$FB_EXISTED" == true ] && echo "(existing)" || echo "$FB_PASS") |
EOF

chmod 600 "$SUMMARY_FILE"
chown "$USER:$USER" "$SUMMARY_FILE"
log "[✓] Summary saved → $SUMMARY_FILE"
