#!/usr/bin/env bash
set -e

LOG_FILE="$LOG_DIR/add_wp_site.log"

DOMAIN=""
PHP_VERSION=""
SSL_TYPE=""
APP=""
HTTP3="off"
MODE="multi"
FSS_PLUGIN_PATH="$FSS_DATA/wp/fsscache"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -php) PHP_VERSION="$2"; shift 2 ;;
    -ssl) SSL_TYPE="$2"; shift 2 ;;
    -app) APP="$2"; shift 2 ;;
    -http3) HTTP3="on"; shift ;;
    --mode) MODE="$2"; shift 2 ;;
    *) echo "[x] Unknown arg: $1"; exit 1 ;;
  esac
done

validate_domain "$DOMAIN"
validate_php_version "$PHP_VERSION"
validate_app_type "$APP"

CREATE_NEW_USER=true

if [[ "$MODE" == "single" ]]; then
  DEFAULT_USER="$(get_default_username "$DOMAIN")"

  echo ""
  echo "Domain: $DOMAIN"
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

PASS=$(generate_password)
USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN/public_html"

FPM_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/$DOMAIN.conf"
FPM_SOCK="/run/php/php-fpm-$DOMAIN.sock"

DB_NAME="$(echo "${DOMAIN//[.-]/_}" | cut -c1-64)"
DB_USER="$(echo "${DOMAIN//[.-]/_}" | cut -c1-32)"

NGINX_CONF="/etc/nginx/sites-available/$DOMAIN.conf"
NGINX_LINK="/etc/nginx/sites-enabled/$DOMAIN.conf"

if [[ -f "$NGINX_CONF" ]]; then
  log "[x] Nginx vhost already exists: $NGINX_CONF"
  exit 1
fi

if [[ "$APP" == "wordpress" ]]; then
  VHOST_TEMPLATE="$FSS_CONF/nginx/custom-vhost.conf"
else
  VHOST_TEMPLATE="$FSS_CONF/nginx/custom-vhost-general.conf"
fi

POOL_TEMPLATE="$FSS_CONF/php/$PHP_VERSION/pool.d/custom.conf"

check_mysql_root_password
MYSQL_ROOT_PASSWORD=$(< "$MYSQL_PASS_FILE")

if mariadb -u root -p"$MYSQL_ROOT_PASSWORD" -e "SELECT 1 FROM mysql.user WHERE User='$DB_USER' AND Host='localhost'" 2>/dev/null | grep -q 1; then
  log "[x] DB user '$DB_USER' already exists. Domain mungkin sudah pernah dibuat."
  exit 1
fi

DB_PASS=$(generate_password)

if [[ "$MODE" == "single" ]]; then
  if [[ "$CREATE_NEW_USER" == true ]]; then
    log "Creating user $USER..."
    useradd -m -d "$USER_HOME" -s /bin/bash -G nginx "$USER"
    echo "$USER:$PASS" | chpasswd
  else
    usermod -aG nginx "$USER" 2>/dev/null || true
    log "Using existing user $USER"
  fi
else
  if ! id "$USER" &>/dev/null; then
    log "Creating user $USER..."
    useradd -m -d "$USER_HOME" -s /bin/bash -G nginx "$USER"
    echo "$USER:$PASS" | chpasswd
  else
    usermod -aG nginx "$USER" 2>/dev/null || true
    log "User $USER already exists, skipping"
  fi
fi

echo "$PHP_VERSION" > "$USER_HOME/.php_version"
echo "$PHP_VERSION" > "$USER_HOME/.php_version_$DOMAIN"

mkdir -p "$SITE_DIR" "$USER_HOME/tmp/php_sessions"
mkdir -p "$USER_HOME/logs/$DOMAIN/nginx"
mkdir -p "$USER_HOME/logs/$DOMAIN/php"
chown "$USER":"$USER" "$USER_HOME"
chown -R "$USER":"$USER" "$USER_HOME/$DOMAIN" "$USER_HOME/tmp" "$USER_HOME/logs/$DOMAIN"
chmod 711 "$USER_HOME"
chmod 755 "$USER_HOME/$DOMAIN"
chmod 755 "$USER_HOME/$DOMAIN/public_html"

log "Configuring PHP-FPM pool for $DOMAIN..."
cp "$POOL_TEMPLATE" "$FPM_CONF"
sed -i "s/\[custom\.com\]/[$DOMAIN]/g" "$FPM_CONF"
sed -i "s/custom\.com/$DOMAIN/g" "$FPM_CONF"
sed -i "s/stack-custom/$USER/g" "$FPM_CONF"
sed -i "s|php_admin_value\[open_basedir\].*|php_admin_value[open_basedir] = /home/$USER/$DOMAIN:/tmp:/usr/share/php:/usr/lib/php:/var/cache/nginx/cache|" "$FPM_CONF"
sed -i "s|php_admin_value\[error_log\].*|php_admin_value[error_log] = /home/$USER/logs/$DOMAIN/php/error.log|" "$FPM_CONF"
sed -i "s|listen = .*|listen = $FPM_SOCK|" "$FPM_CONF"

maxc=$(calc_max_children)
sed -i "s/^pm.max_children = .*/pm.max_children = $maxc/" "$FPM_CONF"
log "[PHP-FPM] Pool created: $DOMAIN (user=$USER, max_children=$maxc)"

systemctl reload php$PHP_VERSION-fpm

log "Configuring NGINX vhost..."
cp "$VHOST_TEMPLATE" "$NGINX_CONF"
sed -i "s|\$USER|$USER|g; s|\$DOMAIN|$DOMAIN|g" "$NGINX_CONF"

mkdir -p /home/"$USER"/logs/"$DOMAIN"/nginx

ln -sf "$NGINX_CONF" "$NGINX_LINK"

log "Creating MariaDB database and user..."

TMP_SQL=$(mktemp)

cat > "$TMP_SQL" <<EOF
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

if ! mariadb -u root -p"$MYSQL_ROOT_PASSWORD" < "$TMP_SQL"; then
  log "[x] ERROR: Failed to create database or user."
  rm -f "$TMP_SQL"
  exit 1
fi

rm -f "$TMP_SQL"

if ! mariadb -u"$DB_USER" -p"$DB_PASS" -e "USE \`$DB_NAME\`;" 2>/dev/null; then
  log "[x] ERROR: Could not connect to database $DB_NAME with user $DB_USER"
  exit 1
fi

log "[✓] Database and user created successfully."

if [[ "$APP" == "wordpress" ]]; then

  log "Installing WordPress..."

  if ! command -v wp >/dev/null 2>&1; then
    log "Downloading WP-CLI..."
    curl -s -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
    chmod +x wp-cli.phar
    mv wp-cli.phar /usr/local/bin/wp
  fi

  log "Downloading WordPress core..."
  sudo -u "$USER" -i -- wp --path="$SITE_DIR" core download --quiet

  log "Creating wp-config.php..."
  sudo -u "$USER" -i -- wp --path="$SITE_DIR" config create \
    --dbname="$DB_NAME" \
    --dbuser="$DB_USER" \
    --dbpass="$DB_PASS" \
    --dbhost="localhost" \
    --skip-check \
    --quiet

  ADMIN_USER="$USER"
  ADMIN_PASS=$(generate_password)
  ADMIN_EMAIL="admin@$DOMAIN"
  SITE_TITLE="Welcome to $DOMAIN"

  if sudo -u "$USER" -i -- wp --path="$SITE_DIR" core is-installed; then
    log "[i] WordPress already installed! Skipping wp core install."
  else
    log "Running wp core install..."
    sudo -u "$USER" -i -- wp --path="$SITE_DIR" core install \
      --url="https://$DOMAIN" \
      --title="$SITE_TITLE" \
      --admin_user="$ADMIN_USER" \
      --admin_password="$ADMIN_PASS" \
      --admin_email="$ADMIN_EMAIL" \
      --skip-email \
      --quiet
  fi

  sudo -u "$USER" -i -- wp --path="$SITE_DIR" user check-password "$ADMIN_USER" "$ADMIN_PASS" \
    && log "[✓] WP-CLI password verified OK" \
    || log "[x] WP-CLI password verification FAILED"

  log "[✓] WordPress installed successfully."

  log ">> Installing Redis support for WordPress..."

  REDIS_READY=true
  REDIS_SOCKET="/run/redis/redis.sock"
  REDIS_USE_SOCKET=false

  if ! systemctl is-active --quiet redis-server; then
    log "[i] Redis server is not running. Skipping Redis setup for WP."
    REDIS_READY=false
  fi

  if ! php$PHP_VERSION -m | grep -qi "^redis$"; then
    log "[i] PHP extension php$PHP_VERSION-redis is not active. Skipping Redis setup."
    REDIS_READY=false
  fi

  if [[ "$REDIS_READY" == true ]]; then
    if [[ -S "$REDIS_SOCKET" ]] && redis-cli -s "$REDIS_SOCKET" ping >/dev/null 2>&1; then
      REDIS_USE_SOCKET=true
      log "[✓] Redis unix socket detected & responding → using socket"
    elif redis-cli ping >/dev/null 2>&1; then
      REDIS_USE_SOCKET=false
      log "[✓] Redis TCP responding → using TCP fallback"
    else
      log "[i] Redis not responding via socket or TCP. Skipping Redis setup."
      REDIS_READY=false
    fi
  fi

  if [[ "$REDIS_READY" == false ]]; then
    log ">> Redis requirements not met. Skipping WordPress Redis integration."
  else
    if [[ "$REDIS_USE_SOCKET" == true ]]; then
      usermod -aG redis "$USER"
      log "[✓] User $USER added to redis group (socket access)"
    fi

    log "Installing Redis Object Cache plugin..."
    sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin install redis-cache --activate --quiet

    if ! grep -q "WP_REDIS_" "$SITE_DIR/wp-config.php"; then

      PREFIX_REDIS="${DOMAIN//./_}_"

      if [[ "$REDIS_USE_SOCKET" == true ]]; then
        cat <<EOF >> "$SITE_DIR/wp-config.php"

define( 'WP_REDIS_SCHEME', 'unix' );
define( 'WP_REDIS_PATH', '$REDIS_SOCKET' );
define( 'WP_REDIS_PREFIX', '$PREFIX_REDIS' );
define( 'WP_REDIS_MAXTTL', 3600 );
define('WP_REDIS_IGBINARY', false);
define('WP_REDIS_SERIALIZER', 'php');
define('WP_REDIS_DATABASE', 0);
define('WP_REDIS_TIMEOUT', 1);
define('WP_REDIS_READ_TIMEOUT', 1);
define( 'WP_REDIS_DISABLED', false );

EOF
        log ">> Redis config (socket) appended to wp-config.php"
      else
        cat <<EOF >> "$SITE_DIR/wp-config.php"

define( 'WP_REDIS_HOST', '127.0.0.1' );
define( 'WP_REDIS_PORT', 6379 );
define( 'WP_REDIS_PREFIX', '$PREFIX_REDIS' );
define( 'WP_REDIS_MAXTTL', 3600 );
define( 'WP_REDIS_DISABLED', false );

EOF
        log ">> Redis config (TCP) appended to wp-config.php"
      fi

    else
      log "[i] Redis already configured in wp-config.php"
    fi

    log "Enabling Redis cache..."
    sudo -u "$USER" -i -- wp --path="$SITE_DIR" redis enable --quiet

    if sudo -u "$USER" -i -- wp --path="$SITE_DIR" redis status >/dev/null 2>&1; then
      log "[✓] Redis Object Cache enabled for $DOMAIN (mode: $([ "$REDIS_USE_SOCKET" == true ] && echo 'socket' || echo 'TCP'))"
    else
      log "[x] Redis enable failed for $DOMAIN"
    fi
  fi

  log ">> Cleaning default WP plugins & themes..."

  sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin delete akismet --quiet || true
  sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin delete hello --quiet || true

  log ">> Installing essential plugins..."

  sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin install classic-editor --activate --quiet
  sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin install wordpress-seo --activate --quiet

  log ">> Removing inactive themes..."
  INACTIVE_THEMES=$(sudo -u "$USER" -i -- wp --path="$SITE_DIR" theme list --status=inactive --field=name)
  if [[ -n "$INACTIVE_THEMES" ]]; then
    for th in $INACTIVE_THEMES; do
      sudo -u "$USER" -i -- wp --path="$SITE_DIR" theme delete "$th" --quiet || true
    done
    log ">> Deleted inactive themes: $INACTIVE_THEMES"
  else
    log "[i] No inactive themes found."
  fi

  log "[✓] WP theme & plugin optimization completed."

  log ">> Setting up Smart Cache Manager (Purge + Preload)..."
  PLUGIN_ZIP="$FSS_PLUGIN_PATH/fss-cache-manager.zip"

  if [[ ! -f "$PLUGIN_ZIP" ]]; then
    log "[!] FSS Cache Manager zip not found: $PLUGIN_ZIP — skipping"
  else
    sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin install "$PLUGIN_ZIP" --activate --quiet

    if sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin is-active fss-cache-manager; then
      log "[✓] FSS Cache Manager installed & activated."
    else
      log "[x] WARNING: Plugin installed but activation failed."
    fi

    log "[✓] Smart Cache Purge & Preload configured."
  fi

fi

setup_ssl "$SSL_TYPE" "$DOMAIN" "$NGINX_CONF" "$HTTP3"

FB_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)
FB_EXISTED=false
FB_RC=0
setup_fb_user "$USER" "$FB_PASS" || FB_RC=$?
[[ $FB_RC -eq 2 ]] && FB_EXISTED=true

setup_logrotate "$USER"

log "Site $DOMAIN created successfully!"
echo "--------------------------------------------"
echo "Site:           https://$DOMAIN"
echo "User:           $USER"
if [[ "$MODE" == "single" && "$CREATE_NEW_USER" == true ]] || [[ "$MODE" == "multi" ]]; then
  echo "User Pass:      $PASS"
fi
echo "DB Name:        $DB_NAME"
echo "DB User:        $DB_USER"
echo "DB Pass:        $DB_PASS"
echo "Root Folder:    $SITE_DIR"
if [[ "$MODE" == "single" ]]; then
  echo "Logs:           $USER_HOME/logs/$DOMAIN/"
  echo "PHP Pool:       $FPM_CONF (per-domain)"
  echo "FPM Socket:     $FPM_SOCK"
fi
if [[ "$APP" == "wordpress" ]]; then
  echo "WP Admin URL:   https://$DOMAIN/wp-admin"
  echo "WP Username:    $USER"
  echo "WP Password:    $ADMIN_PASS"
fi
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
Type: PHP App ($APP)
User: $USER ($([ "$CREATE_NEW_USER" == true ] && echo "new" || echo "existing"))

## Server

| Key | Value |
|-----|-------|
| Domain | $DOMAIN |
| User | $USER |
| Root | $SITE_DIR |
| Logs | $USER_HOME/logs/$DOMAIN/ |
| PHP | $PHP_VERSION |
| FPM Pool | $FPM_CONF |
| SSL | ${SSL_TYPE:-none} |

## Database

| Key | Value |
|-----|-------|
| DB Name | $DB_NAME |
| DB User | $DB_USER |
| DB Pass | $DB_PASS |
| Host | localhost |

## File Manager

| Key | Value |
|-----|-------|
| URL | https://$DOMAIN/fm |
| Username | $USER |
| Password | $([ "$FB_EXISTED" == true ] && echo "(existing)" || echo "$FB_PASS") |
EOF

if [[ "$APP" == "wordpress" ]]; then
cat >> "$SUMMARY_FILE" <<EOF

## WordPress

| Key | Value |
|-----|-------|
| Admin URL | https://$DOMAIN/wp-admin |
| Username | $USER |
| Password | $ADMIN_PASS |
| Email | admin@$DOMAIN |
EOF
fi

chmod 600 "$SUMMARY_FILE"
chown "$USER:$USER" "$SUMMARY_FILE"
log "[✓] Summary saved → $SUMMARY_FILE"
