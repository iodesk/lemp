#!/usr/bin/env bash
set -e

# ====================
# CONFIG & FUNCTIONS
# ====================

REMOTE_CONF_BASE="https://vps.fio.link/conf"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
LOG_FILE="/var/log/add_wp_site.log"

mycurl() { curl -fsSL -A "$CURL_UA" "$@"; }

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

generate_password() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
}

usage() {
  echo "Usage: add-site.sh -d domain.com -php 8.3 -ssl le"
  exit 1
}

is_valid_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

is_supported_php() {
  [[ "$1" == "8.3" || "$1" == "8.2" || "$1" == "8.1" ]]
}

# ====================
# DOMAIN → USER
# ====================
get_user_from_domain() {
  local domain="$1"
  IFS='.' read -ra parts <<< "$domain"
  local num_parts="${#parts[@]}"

  if [[ $num_parts -lt 2 ]]; then
    echo "invalid"
    return 1
  fi

  if [[ $num_parts -eq 2 ]]; then
    echo "${parts[0]}"
  else
    local base="${parts[$num_parts-3]}"
    local sub="${parts[0]}"
    echo "${base}-${sub}"
  fi
}

# ====================
# PARSE ARGUMENTS
# ====================

DOMAIN=""
PHP_VERSION=""
SSL_TYPE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain) DOMAIN="$2"; shift 2 ;;
    -php) PHP_VERSION="$2"; shift 2 ;;
    -ssl) SSL_TYPE="$2"; shift 2 ;; # le | none
    *) echo "Unknown arg: $1"; usage ;;
  esac
done

[[ -z "$DOMAIN" || -z "$PHP_VERSION" ]] && usage
is_valid_domain "$DOMAIN" || { echo "Invalid domain: $DOMAIN"; exit 1; }
is_supported_php "$PHP_VERSION" || { echo "Unsupported PHP version: $PHP_VERSION"; exit 1; }

# ====================
# SETUP VARS
# ====================

USER="$(get_user_from_domain "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
PASS=$(generate_password)
USER_HOME="/home/$USER"
SITE_DIR="$USER_HOME/$DOMAIN/public_html"

FPM_CONF="/etc/php/$PHP_VERSION/fpm/pool.d/${USER}.conf"
NGINX_CONF="/etc/nginx/sites-available/${USER}-vhost.conf"
NGINX_LINK="/etc/nginx/sites-enabled/${USER}-vhost.conf"

POOL_URL="$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/custom.conf"
VHOST_URL="$REMOTE_CONF_BASE/nginx/custom-vhost.conf"

DB_NAME="${USER}"
DB_USER="${USER}"
DB_PASS=$(generate_password)
MYSQL_ROOT_PASSWORD=$(cat /root/.mysql_root_password)

# ====================
# CREATE USER & DIR
# ====================

if ! id "$USER" &>/dev/null; then
  log "Creating user $USER..."
  useradd -m -d "$USER_HOME" -s /bin/bash "$USER"
  echo "$USER:$PASS" | chpasswd
else
  log "User $USER already exists, skipping"
fi

echo "$PHP_VERSION" > "$USER_HOME/.php_version"
mkdir -p "$SITE_DIR" "$USER_HOME/tmp/php_sessions"
mkdir -p "$SITE_DIR" "$USER_HOME/logs/php"
chown -R "$USER":"$USER" "$USER_HOME"
chmod 711 "$USER_HOME"
chmod 755 "$USER_HOME/$DOMAIN"
chmod 755 "$USER_HOME/$DOMAIN/public_html"

# ====================
# CONFIGURE PHP-FPM
# ====================
calc_max_children() {
  local ram_mb
  ram_mb=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
  local per_worker=50
  local usable_ram=$(( ram_mb * 60 / 100 ))
  local max_children=$(( usable_ram / per_worker ))
  if (( max_children < 8 )); then
    max_children=8
  fi

  echo "$max_children"
}

log "Downloading PHP-FPM pool config..."
mycurl "$POOL_URL" > "$FPM_CONF"
sed -i "s/custom.com/$DOMAIN/g; s/stack-custom/$USER/g" "$FPM_CONF"

maxc=$(calc_max_children)
sed -i "s/^pm.max_children = .*/pm.max_children = $maxc/" "$FPM_CONF"
log "[PHP-FPM] Auto pm.max_children set to $maxc based on RAM"

systemctl reload php$PHP_VERSION-fpm

# ====================
# CONFIGURE NGINX
# ====================

log "Downloading NGINX vhost config..."
mycurl "$VHOST_URL" > "$NGINX_CONF"
sed -i "s|\$USER|$USER|g; s|\$DOMAIN|$DOMAIN|g" "$NGINX_CONF"
mkdir -p /home/"$USER"/logs/nginx

ln -sf "$NGINX_CONF" "$NGINX_LINK"

# =====================================
# CREATE DATABASE & USER
# =====================================
log "Creating MariaDB database and user..."

MYSQL_ROOT_PASSWORD=$(< /root/.mysql_root_password)

if [[ -z "$MYSQL_ROOT_PASSWORD" ]]; then
  log "[x] ERROR: MariaDB root password not found at /root/.mysql_root_password"
  exit 1
fi

TMP_SQL=$(mktemp)

cat > "$TMP_SQL" <<EOF
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED WITH mysql_native_password;
SET PASSWORD FOR '$DB_USER'@'localhost' = PASSWORD('$DB_PASS');
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

if ! mariadb -u root -p"$MYSQL_ROOT_PASSWORD" < "$TMP_SQL"; then
  log "[x] ERROR: Failed to create database or user. Check MariaDB root password and permissions."
  rm -f "$TMP_SQL"
  exit 1
fi

rm -f "$TMP_SQL"

if ! mariadb -u"$DB_USER" -p"$DB_PASS" -e "USE \`$DB_NAME\`;" 2>/dev/null; then
  log "[x] ERROR: Could not connect to database $DB_NAME with user $DB_USER"
  exit 1
fi

log "[✓] Database and user created successfully."

# ====================
# INSTALL WORDPRESS
# ====================

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

log "Testing database connection..."
if ! mysql -u"$DB_USER" -p"$DB_PASS" -e "USE $DB_NAME;" 2>/dev/null; then
  log "[x] ERROR: Could not connect to database $DB_NAME with user $DB_USER"
  exit 1
fi

ADMIN_USER="$USER"
ADMIN_PASS=$(generate_password)
ADMIN_EMAIL="admin@$DOMAIN"
SITE_TITLE="Welcome to $DOMAIN"

log "Checking if WordPress is already installed..."
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

echo "Admin WP Login: $ADMIN_USER" >> "$LOG_FILE"
echo "Admin WP Pass : $ADMIN_PASS" >> "$LOG_FILE"
log "[✓] WordPress installed successfully."

# ============================
# REDIS FOR WORDPRESS
# ============================
log ">> Installing Redis support for WordPress..."

REDIS_READY=true

if ! systemctl is-active --quiet redis-server; then
  log "[i] Redis server is not running. Skipping Redis setup for WP."
  REDIS_READY=false
fi

if ! php$PHP_VERSION -m | grep -qi "^redis$"; then
  log "[i] PHP extension php$PHP_VERSION-redis is not active. Skipping Redis setup."
  REDIS_READY=false
fi

if ! redis-cli ping >/dev/null 2>&1; then
  log "[i] redis-cli PING failed. Redis not responding. Skipping Redis setup."
  REDIS_READY=false
fi

if [[ "$REDIS_READY" == false ]]; then
  log ">> Redis requirements not met. Skipping WordPress Redis integration."
else
  log "[✓] Redis environment OK. Enabling Redis for WordPress..."

  log "Installing Redis Object Cache plugin..."
  sudo -u "$USER" -i -- wp --path="$SITE_DIR" plugin install redis-cache --activate --quiet

  if ! grep -q "WP_REDIS_HOST" "$SITE_DIR/wp-config.php"; then
  
  PREFIX_REDIS="${DOMAIN//./_}_"

    cat <<EOF >> "$SITE_DIR/wp-config.php"

// Redis settings
define( 'WP_REDIS_HOST', '127.0.0.1' );
define( 'WP_REDIS_PORT', 6379 );
define( 'WP_REDIS_PREFIX', '$PREFIX_REDIS' );
define( 'WP_REDIS_MAXTTL', 3600 );
define( 'WP_REDIS_DISABLED', false );

EOF
    log ">> Redis config appended to wp-config.php"
  else
    log "[i] Redis already configured in wp-config.php"
  fi

  log "Enabling Redis cache..."
  sudo -u "$USER" -i -- wp --path="$SITE_DIR" redis enable --quiet

  if sudo -u "$USER" -i -- wp --path="$SITE_DIR" redis status >/dev/null 2>&1; then
    log "[✓] Redis Object Cache successfully enabled for $DOMAIN"
  else
    log "[x] Redis enable failed for $DOMAIN"
  fi

fi

# ============================
# WORDPRESS: CLEANUP + ESSENTIAL PLUGINS
# ============================
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


# ====================
# SSL (LETS ENCRYPT)
# ====================

if [[ "$SSL_TYPE" == "le" ]]; then
  log "🔐 [LE] Preparing dummy certificate for initial NGINX config..."

  DUMMY_DIR="/etc/ssl/selfsigned"
  DUMMY_CERT="$DUMMY_DIR/$DOMAIN.crt"
  DUMMY_KEY="$DUMMY_DIR/$DOMAIN.key"
  mkdir -p "$DUMMY_DIR"

  if [[ ! -f "$DUMMY_CERT" || ! -f "$DUMMY_KEY" ]]; then
    openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
      -keyout "$DUMMY_KEY" \
      -out "$DUMMY_CERT" \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$DOMAIN"
    log "[✓] Dummy SSL generated for $DOMAIN"
  else
    log "[i] Dummy SSL already exists for $DOMAIN"
  fi

  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 ssl;|listen [::]:443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $DUMMY_CERT;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $DUMMY_KEY;|g" "$NGINX_CONF"

  if ! grep -q "ssl_certificate " "$NGINX_CONF"; then
    log "[x] ERROR: ssl_certificate not found after sed"
    exit 1
  fi

  if nginx -t; then
    systemctl reload nginx
    log "[✓] NGINX reloaded with dummy cert"
  else
    log "[x] ERROR: NGINX config invalid after dummy cert config"
    exit 1
  fi

  # ============================
  # AUTO DETECT WWW DNS
  # ============================

  if dig +short www.$DOMAIN >/dev/null 2>&1 | grep -qE '.'; then
    REQUEST_WWW=true
    log "🌐 DNS www.$DOMAIN detected → requesting www + non-www"
  else
    REQUEST_WWW=false
    log "🌐 No DNS for www.$DOMAIN → requesting non-www only"
  fi

  # ============================
  # REQUEST LET'S ENCRYPT
  # ============================

  if [[ "$REQUEST_WWW" == true ]]; then

    if certbot certonly --nginx --non-interactive --agree-tos --email "admin@$DOMAIN" \
      -d "$DOMAIN" -d "www.$DOMAIN"; then
      log "[✓] Certbot succeeded with www and non-www"
    else
      log "[i] Certbot failed with www.$DOMAIN, retrying without www..."
      if certbot certonly --nginx --non-interactive --agree-tos --email "admin@$DOMAIN" -d "$DOMAIN"; then
        log "[✓] Certbot succeeded without www"
      else
        log "[x] Certbot failed. Keeping dummy cert."
        exit 1
      fi
    fi

  else

    if certbot certonly --nginx --non-interactive --agree-tos --email "admin@$DOMAIN" \
      -d "$DOMAIN"; then
      log "[✓] Certbot succeeded (non-www only)"
    else
      log "[x] Certbot failed. Keeping dummy cert."
      exit 1
    fi

  fi

  # ============================
  # APPLY REAL CERT
  # ============================

  REAL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  REAL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"

  if [[ -f "$REAL_CERT" && -f "$REAL_KEY" ]]; then
    sed -i "s|ssl_certificate .*|ssl_certificate $REAL_CERT;|g" "$NGINX_CONF"
    sed -i "s|ssl_certificate_key .*|ssl_certificate_key $REAL_KEY;|g" "$NGINX_CONF"

    if nginx -t; then
      systemctl reload nginx
      log "🔄 NGINX reloaded with Let's Encrypt certificate"
    else
      log "[x] ERROR: NGINX config invalid after switching to real cert"
      exit 1
    fi
  else
    log "[x] ERROR: Certbot succeeded but cert files not found"
    exit 1
  fi

# ====================
# SSL (SELF SIGNED)
# ====================

elif [[ "$SSL_TYPE" == "self" ]]; then
  log "🔐 [SELF] Preparing self-signed certificate for NGINX..."

  DUMMY_DIR="/etc/ssl/selfsigned"
  DUMMY_CERT="$DUMMY_DIR/$DOMAIN.crt"
  DUMMY_KEY="$DUMMY_DIR/$DOMAIN.key"
  mkdir -p "$DUMMY_DIR"

  if [[ ! -f "$DUMMY_CERT" || ! -f "$DUMMY_KEY" ]]; then
    openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
      -keyout "$DUMMY_KEY" \
      -out "$DUMMY_CERT" \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$DOMAIN"
    log "[✓] Self-signed SSL generated for $DOMAIN"
  else
    log "[i] Self-signed SSL already exists for $DOMAIN"
  fi

  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 ssl;|listen [::]:443 ssl;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $DUMMY_CERT;|g" "$NGINX_CONF"
  sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $DUMMY_KEY;|g" "$NGINX_CONF"

  if ! grep -q "ssl_certificate " "$NGINX_CONF"; then
    log "[x] ERROR: ssl_certificate not found after sed"
    exit 1
  fi

  if nginx -t; then
    systemctl reload nginx
    log "[✓] NGINX reloaded with self-signed SSL"
  else
    log "[x] ERROR: NGINX config invalid after self-signed config"
    exit 1
  fi


# ============================
# CRON RENEW
# ============================

  CRON_RENEW="/etc/cron.d/certbot_renew"
  if [[ ! -f "$CRON_RENEW" ]]; then
    echo "0 3 * * * root certbot renew --quiet --post-hook \"systemctl reload nginx\"" > "$CRON_RENEW"
    log "⏰ Certbot auto-renewal cron added"
  else
    log "⏰ Certbot auto-renewal cron already exists"
  fi
fi

# ============================
# Filemanager
# ============================
FB_HOST="http://127.0.0.1:2222"
FB_TOKEN_FILE="/root/.filebrowser_token"

  if [[ ! -f "$FB_TOKEN_FILE" ]]; then
    log "[FB] ERROR: Token file not found → $FB_TOKEN_FILE"
    log "[FB] Install script must generate token first. Skipping."
    return 1
  fi

  TOKEN=$(cat "$FB_TOKEN_FILE")
  FB_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)

  log "[FB] Creating Filebrowser user: $USER"

JSON_PAYLOAD=$(cat <<EOF
{
  "what": "user",
  "data": {
      "username": "$USER",
      "password": "$FB_PASS",
      "scope": "$USER",
      "locale": "en",
      "viewMode": "list",
      "singleClick": false,
      "commands": [],
      "perm": {
          "admin": false,
          "execute": true,
          "create": true,
          "rename": true,
          "modify": true,
          "delete": true,
          "share": true,
          "download": true
      }
  }
}
EOF
)

HTTP_CODE=$(curl -s -w "%{http_code}" \
  -X POST "$FB_HOST/api/users" \
  -H "X-Auth: $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$JSON_PAYLOAD")

HTTP_CODE=$(echo "$HTTP_CODE" | tail -n1 | tr -dc '0-9')

  if [[ "$HTTP_CODE" == "201" || "$HTTP_CODE" == "200" ]];  then
    log "[FB] User added successfully"
  else
    log "[FB] ERROR creating user (HTTP $HTTP_CODE)"
  fi


# ====================
# SETUP LOGROTATE
# ====================
log "🔐 [LOGROTATE] Creating LOGROTATE for $USER..."

cat >/etc/logrotate.d/$USER.conf <<EOF
/home/$USER/logs/*/*.log {
    su root root
    daily
    missingok
    rotate 30
    dateext
    dateformat -%Y-%m-%d
    create 0640 $USER $USER
    postrotate
      /etc/init.d/nginx reload &> /dev/null || true
    endscript
}
EOF

log "[✓] Logrotate rules created/updated for: $USER"

# ====================
# DONE - OUTPUT INFO
# ====================

log "Site $DOMAIN created successfully!"
echo "--------------------------------------------"
echo "Site:           https://$DOMAIN"
echo "User:           $USER"
echo "User Pass:      $PASS"
echo "DB Name:        $DB_NAME"
echo "DB User:        $DB_USER"
echo "DB Pass:        $DB_PASS"
echo "Root Folder:    $SITE_DIR"
echo "WP Admin URL:   https://$DOMAIN/wp-admin"
echo "WP Username:    $USER"
echo "WP Password:    $ADMIN_PASS"
echo "File Manager:   $FB_HOST"
echo "FM Username:    $USER"
echo "FM Password:    $FB_PASS"
echo "--------------------------------------------"
