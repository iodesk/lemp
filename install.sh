#!/bin/bash
set -e

# ========================================
# CONFIGURABLE VARIABLES
# ========================================
REMOTE_CONF_BASE="https://vps.fio.link/conf"
PHP_VERSION="8.4"
SWAPFILE="/swapfile"
SWAPSIZE="1G"
LOGFILE="/var/log/installer.log"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
MARIADB_VERSION="11.4"

# ========================================
# LOGGING + CURL WRAPPER
# ========================================
mkdir -p "$(dirname "$LOGFILE")"
: > "$LOGFILE"

log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $@" | tee -a "$LOGFILE"
}

logv() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $@" >> "$LOGFILE"
}

run() {
  local desc="$1"; shift
  logv "[RUN] $desc: $*"
  if "$@" >> "$LOGFILE" 2>&1; then
    logv "[OK] $desc"
    return 0
  else
    local rc=$?
    log "[✗] FAILED: $desc (exit $rc) | check $LOGFILE"
    return $rc
  fi
}

mycurl() {
  local url="$1"
  logv "[CURL] $*"
  if curl -fsSL --retry 3 --connect-timeout 5 -A "$CURL_UA" "$@" 2>> "$LOGFILE"; then
    logv "[✓] Download OK: $url"
  else
    log "[✗] Download failed: $url | check $LOGFILE"
    return 1
  fi
}

# ========================================
# OS DETECTION
# ========================================
source /etc/os-release
CODENAME=$VERSION_CODENAME
OS_VERSION=$VERSION_ID
SUPPORTED_OS=("24.04")

check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    log "[!] Please run as root"
    exit 1
  fi
}

is_supported_os() {
  for version in "${SUPPORTED_OS[@]}"; do
    [[ "$OS_VERSION" == "$version" ]] && return 0
  done
  return 1
}

fail_unsupported_os() {
  log "[✗] Unsupported OS version: $OS_VERSION ($CODENAME)"
  log "Only Ubuntu 24.04 (noble) are supported."
  exit 1
}

# ========================================
# Dependencies INSTALLER
# ========================================
install_dependencies(){
  log "[+] Installing dependencies..."
  apt-get install -y software-properties-common curl dirmngr gnupg ca-certificates \
    lsb-release certbot python3-certbot-nginx zip unzip tar jq >> "$LOGFILE" 2>&1
  log "[✓] Dependencies installed."
}

# ========================================
# SWAP INSTALLER
# ========================================
add_swap() {
  if swapon --show | grep -q "$SWAPFILE"; then
    log "[i] Swapfile already exists. Skipping swap creation."
    return
  fi

  log "[+] Creating $SWAPSIZE swapfile..."
  fallocate -l $SWAPSIZE $SWAPFILE >> "$LOGFILE" 2>&1
  chmod 600 $SWAPFILE
  mkswap $SWAPFILE >> "$LOGFILE" 2>&1
  swapon $SWAPFILE >> "$LOGFILE" 2>&1
  echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  log "[✓] Swapfile created and enabled."
}

# ========================================
# INSTALL SYSCTL
# ========================================
install_sysctl() {
    log ">>> [Sysctl] Tuning sysctl..."
    mycurl "$REMOTE_CONF_BASE/sysctl/99-tuning.conf" -o /etc/sysctl.d/99-tuning.conf
    sysctl -p >> "$LOGFILE" 2>&1
    log "[✓] Sysctl tuning applied."
}

# ========================================
# ENABLE TCP BBR
# ========================================
enable_bbr() {

log "=== [BBR] Auto Enable ==="

IFACE=$(ip route get 1.1.1.1 | awk '/dev/ {print $5}' | head -n1)

# ---------------------------------------------
# 1) Check kernel support
# ---------------------------------------------
if ! grep -R "CONFIG_TCP_CONG_BBR" /boot/config-$(uname -r) >/dev/null 2>&1; then
    log "[BBR] NOT found in kernel config -> /boot/config-$(uname -r)"
    log "[BBR] Kernel does not support BBR. Skipping."
    return 0
fi

log "[BBR] Found in kernel config."

# ---------------------------------------------
# 2) Load module
# ---------------------------------------------
if ! lsmod | grep -q tcp_bbr; then
    modprobe tcp_bbr >/dev/null 2>&1 && \
        log "[BBR] tcp_bbr module loaded." || \
        log "[BBR] tcp_bbr may be built-in (no module needed)."
else
    log "[BBR] tcp_bbr module already loaded."
fi

# ---------------------------------------------
# 3) Verify availability
# ---------------------------------------------
AVAILABLE_CC=$(sysctl -n net.ipv4.tcp_available_congestion_control)

if ! echo "$AVAILABLE_CC" | grep -q bbr; then
    log "[BBR] Not listed in congestion control. Skipping."
    return 0
fi

log "[BBR] Listed in congestion control list."

# ---------------------------------------------
# 4) qdisc fq
# ---------------------------------------------
CURRENT_QDISC=$(tc qdisc show dev "$IFACE" | awk '/qdisc/ {print $2}')

if [ "$CURRENT_QDISC" != "fq" ]; then
    log "[BBR] Switching qdisc $CURRENT_QDISC → fq ..."
    tc qdisc replace dev "$IFACE" root fq || {
        log "[BBR] Failed to apply fq. Provider may lock qdisc."
        return 0
    }
else
    log "[BBR] qdisc already fq."
fi

# ---------------------------------------------
# 5) sysctl persistent
# ---------------------------------------------
log "[BBR] Applying sysctl config..."

cat >/etc/sysctl.d/99-bbr-fq.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF

sysctl --system >/dev/null

# ---------------------------------------------
# 6) Verify active
# ---------------------------------------------
ACTIVE_CC=$(sysctl -n net.ipv4.tcp_congestion_control)

if [ "$ACTIVE_CC" = "bbr" ]; then
    log "[BBR] ENABLED SUCCESSFULLY."
else
    log "[BBR] FAILED to enable. Current: $ACTIVE_CC"
    return 0
fi

# ---------------------------------------------
# 7) Optional pacing check
# ---------------------------------------------
if ss -ti | grep -q "pacing_rate"; then
    log "[BBR] TCP pacing detected → fully active."
else
    log "[BBR] WARNING: TCP pacing not detected. May be partial."
fi

log "[BBR] Done."
return 0
}

# ========================================
# INSTALL NGINX
# ========================================
install_nginx() {
  log ">>> [NGINX] Installing NGINX from official nginx.org repo for Ubuntu $OS_VERSION ($CODENAME)..."
  is_supported_os || fail_unsupported_os
  
  useradd -r -s /usr/sbin/nologin nginx

  log ">>> [NGINX] Adding official nginx.org repository..."

  apt-get install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring >> "$LOGFILE" 2>&1

  curl -fsSL https://nginx.org/keys/nginx_signing.key \
    | gpg --dearmor \
    | tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

  KEY_FP=$(gpg --dry-run --quiet --no-keyring --import --import-options import-show \
    /usr/share/keyrings/nginx-archive-keyring.gpg 2>/dev/null | grep -o "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62")

  if [[ "$KEY_FP" != "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62" ]]; then
    log "[✗] ERROR: nginx signing key verification failed!"
    log "    Expected fingerprint: 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"
    exit 1
  fi
  log "[✓] nginx signing key verified."

  echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/ubuntu $(lsb_release -cs) nginx" \
    | tee /etc/apt/sources.list.d/nginx.list > /dev/null

  cat > /etc/apt/preferences.d/99-nginx <<EOF
Package: *
Pin: origin nginx.org
Pin: release o=nginx
Pin-Priority: 900
EOF

  APT_OUTPUT=$(apt-get update 2>&1)
  echo "$APT_OUTPUT" >> "$LOGFILE"

  if echo "$APT_OUTPUT" | grep -qiE "403|forbidden|failed to fetch|is not signed"; then
    log "[✗] ERROR: nginx.org repository not reachable."
    log "    Possible causes:"
    log "    - Repository blocked by hosting provider (403 Forbidden)"
    log "    - Network/DNS issue on this server"
    log "    Aborting nginx installation."
    exit 1
  fi

  log ">>> [NGINX] Installing nginx..."
  apt-get install -y nginx >> "$LOGFILE" 2>&1

  log ">>> [NGINX] Fetching remote NGINX config..."
  mkdir -p /etc/nginx/{sites-enabled,sites-available,conf.d,includes} /var/cache/nginx/cache
  chown -R nginx:nginx /var/cache/nginx/cache
  chmod 2770 /var/cache/nginx/cache
  touch /etc/nginx/includes/{global.conf,be-proc-global.conf,fe-proc-global.conf}
  mkdir -p /etc/nginx/ssl  
  mkdir -p /etc/nginx/modules-available
  mkdir -p /etc/nginx/modules-enabled  

  openssl dhparam -dsaparam -out /etc/nginx/ssl/dhparams.pem 2048 >> "$LOGFILE" 2>&1
  chmod 600 /etc/nginx/ssl/dhparams.pem
  chown root:root /etc/nginx/ssl/dhparams.pem
  
  rm -rf /etc/nginx/sites-available/default
  rm -rf /etc/nginx/sites-enabled/default

  cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak 2>/dev/null
  mycurl "$REMOTE_CONF_BASE/nginx/nginx.conf" -o /etc/nginx/nginx.conf
  mycurl "$REMOTE_CONF_BASE/nginx/00-default.conf" -o /etc/nginx/sites-enabled/00-default.conf
  mycurl "$REMOTE_CONF_BASE/nginx/custom-vhost.conf" -o /etc/nginx/sites-available/custom-vhost.conf.example

  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/gzip.conf" -o /etc/nginx/conf.d/gzip.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/brotli.conf" -o /etc/nginx/conf.d/brotli.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/cloudflare.conf" -o /etc/nginx/conf.d/cloudflare.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/header-sec.conf" -o /etc/nginx/conf.d/header-sec.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/wp-map.conf" -o /etc/nginx/conf.d/wp-map.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/7g-firewall.conf" -o /etc/nginx/conf.d/7g-firewall.conf
  mycurl "$REMOTE_CONF_BASE/nginx/mime.types" -o /etc/nginx/mime.types
  touch /etc/nginx/conf.d/botblocker-nginx-settings.conf
  touch /etc/nginx/conf.d/globalblacklist.conf
  #touch /etc/nginx/modules-available/brotli.conf
  mkdir -p /etc/nginx/bots.d
  touch /etc/nginx/bots.d/{bad-referrer-words.conf,blacklist-ips.conf,blacklist-user-agents.conf,blockbots.conf,custom-bad-referrers.conf,ddos.conf,whitelist-domains.conf,whitelist-ips.conf}

  mycurl "$REMOTE_CONF_BASE/nginx/includes/fe-proc-global.conf" -o /etc/nginx/includes/fe-proc-global.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/fe-proc-global.conf" -o /etc/nginx/includes/be-proc-global.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/security-rules.conf" -o /etc/nginx/includes/security-rules.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/static.conf" -o /etc/nginx/includes/static.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/fastcgi.conf" -o /etc/nginx/includes/fastcgi.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/7g.conf" -o /etc/nginx/includes/7g.conf 
  mycurl "$REMOTE_CONF_BASE/nginx/includes/crawler.conf" -o /etc/nginx/includes/crawler.conf

  mkdir -p /var/cache/nginx/cache
  chmod -R 2770 /var/cache/nginx/cache

  # ACL: ensure nginx group can always read/write/delete cache files
  # This allows PHP-FPM (group=nginx) to purge cache created by nginx worker
  apt-get install -y acl >> "$LOGFILE" 2>&1
  setfacl -R -m g:nginx:rwx /var/cache/nginx/cache
  setfacl -R -d -m g:nginx:rwx /var/cache/nginx/cache

#cat <<'EOF' > /etc/nginx/modules-available/brotli.conf
#load_module modules/ngx_http_brotli_filter_module.so;
#load_module modules/ngx_http_brotli_static_module.so;
#EOF
#ln -sf /etc/nginx/modules-available/brotli.conf /etc/nginx/modules-enabled/brotli.conf

  log ">>> [NGINX] Restarting..."
  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl enable nginx >> "$LOGFILE" 2>&1
  systemctl restart nginx >> "$LOGFILE" 2>&1
  log ">>> [NGINX] Installation complete."
}

# ========================================
# INSTALL PHP
# ========================================
install_php() {
  log ">>> [PHP] Installing PHP ($PHP_VERSION)..."
  is_supported_os || fail_unsupported_os

  log ">>> [PHP] Adding Ondřej PHP PPA..."
  mycurl "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x4F4EA0AAE5267A6C" \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/ondrej-php.gpg

  add-apt-repository -y "deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu $CODENAME main" >> "$LOGFILE" 2>&1
  add-apt-repository -y "deb-src https://ppa.launchpadcontent.net/ondrej/php/ubuntu $CODENAME main" >> "$LOGFILE" 2>&1

  APT_OUTPUT=$(apt-get update 2>&1)
  echo "$APT_OUTPUT" >> "$LOGFILE"

  if echo "$APT_OUTPUT" | grep -qiE "403|forbidden|failed to fetch|is not signed"; then
    log "[✗] ERROR: Ondřej PHP PPA not reachable."
    log "    Possible causes:"
    log "    - PPA blocked by hosting provider (403 Forbidden)"
    log "    - Network/DNS issue on this server"
    log "    - PPA temporarily unavailable"
    log "    Aborting PHP installation."
    exit 1
  fi

  log ">>> [PHP] Installing PHP packages..."
  apt-get install -y php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-cli \
    php$PHP_VERSION-mysql php$PHP_VERSION-curl php$PHP_VERSION-mbstring \
    php$PHP_VERSION-xml php$PHP_VERSION-gd php$PHP_VERSION-zip php$PHP_VERSION-bcmath \
    php${PHP_VERSION}-redis php${PHP_VERSION}-opcache php${PHP_VERSION}-intl >> "$LOGFILE" 2>&1

  cp /etc/php/$PHP_VERSION/fpm/php.ini{,.bak} 2>/dev/null
  log ">>> [PHP] Applying PHP-FPM config..."
  mkdir -p /etc/php/$PHP_VERSION/fpm/conf.d
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/php.ini" -o /etc/php/$PHP_VERSION/fpm/php.ini
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/www.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/custom.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/custom.example

  systemctl restart php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  systemctl enable php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  log ">>> [PHP] Installation complete."

  log ">>> [PHP] Applying OPcache performance settings..."

  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/conf.d/10-opcache.ini" -o "/etc/php/$PHP_VERSION/fpm/conf.d/10-opcache.ini"
  systemctl restart php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  log "[✓] OPcache tuning applied."
    
}

install_ioncube() {
  log ">>> [ionCube] Installing ionCube Loader for PHP $PHP_VERSION..."

  local IONCUBE_DOWNLOAD="https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"
  local WORK_DIR="/tmp/ioncube_install_$$"

  mkdir -p "$WORK_DIR"

  log "[+] Downloading ionCube Loader..."
  curl -sSL "$IONCUBE_DOWNLOAD" -o "$WORK_DIR/ioncube.tar.gz"

  tar -xzf "$WORK_DIR/ioncube.tar.gz" -C "$WORK_DIR"

  local PHP_API_DIR=$(php -i | grep "^extension_dir" | awk '{print $3}')
  local LOADER_FILE="ioncube_loader_lin_${PHP_VERSION}.so"

  if [[ ! -f "$WORK_DIR/ioncube/$LOADER_FILE" ]]; then
      log "[✗] ERROR: ionCube loader for PHP $PHP_VERSION not found! (ionCube might not support this version yet)"
      rm -rf "$WORK_DIR"
      return 1
  fi

  log "[+] Installing ionCube loader → $PHP_API_DIR"
  cp "$WORK_DIR/ioncube/$LOADER_FILE" "$PHP_API_DIR"

  local INI_FILE="/etc/php/$PHP_VERSION/fpm/conf.d/00-ioncube.ini"
  echo "zend_extension=$PHP_API_DIR/$LOADER_FILE" > "$INI_FILE"

  echo "zend_extension=$PHP_API_DIR/$LOADER_FILE" \
      > /etc/php/$PHP_VERSION/cli/conf.d/00-ioncube.ini

  systemctl restart php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  log "[✓] ionCube installed for PHP $PHP_VERSION"

  rm -rf "$WORK_DIR"
  log "[✓] Temporary files removed."
}


# ========================================
# INSTALL MARIADB
# ========================================
install_mariadb() {
  log ">>> [MariaDB] Installing MariaDB $MARIADB_VERSION..."
  is_supported_os || fail_unsupported_os

  log "[+] Adding MariaDB GPG key..."
  mycurl https://mariadb.org/mariadb_release_signing_key.asc \
    | gpg --dearmor -o /usr/share/keyrings/mariadb-keyring.gpg

  log "[+] Adding MariaDB repo..."
  echo "deb [signed-by=/usr/share/keyrings/mariadb-keyring.gpg] https://mirror.mariadb.org/repo/$MARIADB_VERSION/ubuntu $CODENAME main" \
    > /etc/apt/sources.list.d/mariadb.list

  apt-get update >> "$LOGFILE" 2>&1
  DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client >> "$LOGFILE" 2>&1

  log "[+] Applying MariaDB config..."
  rm -rf /etc/mysql/mariadb.conf.d/* 2>/dev/null || true
  mycurl "$REMOTE_CONF_BASE/mariadb/stack-my.cnf" -o /etc/mysql/mariadb.conf.d/99-stack.cnf

  cat > /etc/systemd/system/mariadb.service.d/limits.conf <<EOF
[Service]
LimitNOFILE=65535
#Environment="MYSQLD_OPTS="
#Environment="_WSREP_NEW_CLUSTER="
#Environment="_WSREP_START_POSITION="
EOF

  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl restart mariadb >> "$LOGFILE" 2>&1
  systemctl enable mariadb >> "$LOGFILE" 2>&1

  log "[✓] MariaDB installed."

  log ">>> Securing MariaDB..."
  MYSQL_ROOT_PASSWORD=$(openssl rand -base64 20)

  mysql -u root >> "$LOGFILE" 2>&1 <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '$MYSQL_ROOT_PASSWORD';
DELETE FROM mysql.user WHERE User='';
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF

  echo "$MYSQL_ROOT_PASSWORD" > /root/.mysql_root_password
  chmod 600 /root/.mysql_root_password
  
  log "[✓] MariaDB secured. Root password saved."
}

# ========================================
# INSTALL phpMyAdmin
# ========================================
install_phpmyadmin() {
  log "Installing phpMyAdmin..."

  if ! command -v mariadb >/dev/null; then
    log "[x] MariaDB is not installed."
    return 1
  fi

  PMA_DIR="/usr/share/phpmyadmin"
  if [[ -d "$PMA_DIR" ]]; then
    log "[i] phpMyAdmin already installed."
    return 0
  fi

  TMP_DIR=$(mktemp -d)
  PMA_VER="5.2.1"

  mycurl "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VER}/phpMyAdmin-${PMA_VER}-all-languages.zip" \
    -o "$TMP_DIR/pma.zip"
  unzip -q "$TMP_DIR/pma.zip" -d "$TMP_DIR"

  INNER_DIR=$(find "$TMP_DIR" -maxdepth 1 -type d -name "phpMyAdmin-*")
  mkdir -p "$PMA_DIR"
  mv "$INNER_DIR"/* "$PMA_DIR/"
  rm -rf "$TMP_DIR"

  mkdir -p "$PMA_DIR/tmp"
  chmod 777 "$PMA_DIR/tmp"
  chown -R www-data:www-data "$PMA_DIR"

  cp "$PMA_DIR/config.sample.inc.php" "$PMA_DIR/config.inc.php"
  blowfish_secret=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 32)
  sed -i "s|\['blowfish_secret'\] = ''|\['blowfish_secret'\] = '$blowfish_secret'|" "$PMA_DIR/config.inc.php"

  mkdir -p /tmp/phpmyadmin/{tmp,upload,save}
  chown -R www-data:www-data /tmp/phpmyadmin
  sed -i '/^?>$/d' "$PMA_DIR/config.inc.php"

  cat >> "$PMA_DIR/config.inc.php" <<'PMAEOF'

$cfg['Servers'][$i]['AllowRoot'] = false;
$cfg['TempDir'] = '/tmp/phpmyadmin/tmp';
$cfg['UploadDir'] = '/tmp/phpmyadmin/upload';
$cfg['SaveDir'] = '/tmp/phpmyadmin/save';
$cfg['DefaultLang'] = 'en';
PMAEOF

  chown -R www-data:www-data "$PMA_DIR/config.inc.php"

  mycurl "$REMOTE_CONF_BASE/nginx/includes/phpmyadmin.conf" \
    -o /etc/nginx/includes/phpmyadmin.conf

  mycurl "$REMOTE_CONF_BASE/nginx/includes/filemanager.conf" \
    -o /etc/nginx/includes/filemanager.conf    

  if ! grep -q "phpmyadmin.conf" /etc/nginx/includes/global.conf 2>/dev/null; then
    echo "include /etc/nginx/includes/phpmyadmin.conf;" >> /etc/nginx/includes/global.conf
  fi

  if ! grep -q "filemanager.conf" /etc/nginx/includes/global.conf 2>/dev/null; then
    echo "include /etc/nginx/includes/filemanager.conf;" >> /etc/nginx/includes/global.conf
  fi  

  if ! grep -q "7g.conf" /etc/nginx/includes/global.conf 2>/dev/null; then
    echo "#include /etc/nginx/includes/7g.conf;" >> /etc/nginx/includes/global.conf
  fi    

  nginx -t >> "$LOGFILE" 2>&1 && systemctl reload nginx >> "$LOGFILE" 2>&1
  
  MYSQL_PW="$(cat /root/.mysql_root_password)"

  mysql -u root -p"$MYSQL_PW" >> "$LOGFILE" 2>&1 <<EOF
CREATE DATABASE IF NOT EXISTS phpmyadmin
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
EOF

  mysql -u root -p"$MYSQL_PW" phpmyadmin \
    < /usr/share/phpmyadmin/sql/create_tables.sql >> "$LOGFILE" 2>&1

  ADMINPMA_PASS=$(openssl rand -base64 16)

  mysql -u root -p"$MYSQL_PW" >> "$LOGFILE" 2>&1 <<EOF
CREATE USER IF NOT EXISTS 'adminfss'@'localhost' IDENTIFIED BY '$ADMINPMA_PASS';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER, INDEX,
      CREATE TEMPORARY TABLES, LOCK TABLES, EXECUTE,
      CREATE VIEW, SHOW VIEW, CREATE ROUTINE, ALTER ROUTINE,
      EVENT, TRIGGER, REFERENCES
  ON *.* TO 'adminfss'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

  echo "$ADMINPMA_PASS" > /root/.pma_admin_password
  chmod 600 /root/.pma_admin_password
  log "[✓] PMA admin user 'adminfss' created. Password saved → /root/.pma_admin_password"

  log "[✓] phpMyAdmin installed."
}

# ========================================
# INSTALL FAIL2BAN
# ========================================
install_fail2ban() {
  log ">>> [Fail2Ban] Installing Fail2Ban..."

  apt-get update >> "$LOGFILE" 2>&1
  apt-get install -y fail2ban >> "$LOGFILE" 2>&1

  mkdir -p /etc/fail2ban/{filter.d,jail.d}

  mycurl "$REMOTE_CONF_BASE/fail2ban/filter.d/mysqld-auth.conf" \
    -o /etc/fail2ban/filter.d/mysqld-auth.conf
  mycurl "$REMOTE_CONF_BASE/fail2ban/jail.d/mariadb.conf" \
    -o /etc/fail2ban/jail.d/mariadb.conf

  mycurl "$REMOTE_CONF_BASE/fail2ban/filter.d/wp-login-auth.conf" \
    -o /etc/fail2ban/filter.d/wp-login-auth.conf
  mycurl "$REMOTE_CONF_BASE/fail2ban/jail.d/wp-login-burst.conf" \
    -o /etc/fail2ban/jail.d/wp-login-burst.conf  

  mycurl "$REMOTE_CONF_BASE/fail2ban/filter.d/phpmyadmin-auth.conf" \
    -o /etc/fail2ban/filter.d/phpmyadmin-auth.conf
  mycurl "$REMOTE_CONF_BASE/fail2ban/jail.d/phpmyadmin.conf" \
    -o /etc/fail2ban/jail.d/phpmyadmin.conf

  mycurl "$REMOTE_CONF_BASE/fail2ban/filter.d/filemanager-auth.conf" \
    -o /etc/fail2ban/filter.d/filemanager-auth.conf
  mycurl "$REMOTE_CONF_BASE/fail2ban/jail.d/filemanager.conf" \
    -o /etc/fail2ban/jail.d/filemanager.conf    

  # creatae dummy log for fail2ban
  mkdir -p /home/.fail2ban-placeholder/logs/nginx
  touch /home/.fail2ban-placeholder/logs/nginx/access.log

  systemctl enable fail2ban >> "$LOGFILE" 2>&1
  systemctl restart fail2ban >> "$LOGFILE" 2>&1
  fail2ban-client reload >> "$LOGFILE" 2>&1

  log "[✓] Fail2Ban installed."
  fail2ban-client -d >> "$LOGFILE" 2>&1 || log "[!] Fail2Ban config has warnings — lihat $LOGFILE"
}

# ========================================
# INSTALL IPTABLES
# ========================================
install_iptables() {
  log ">>> [iptables] Installing iptables..."

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables iptables-persistent netfilter-persistent >> "$LOGFILE" 2>&1

  iptables -F
  iptables -X
  iptables -Z

    iptables -A INPUT -i lo -j ACCEPT

    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    iptables -A INPUT ! -i lo -s 127.0.0.0/8 -j DROP
    iptables -A INPUT -s 10.0.0.0/8 -j DROP
    iptables -A INPUT -s 172.16.0.0/12 -j DROP
    iptables -A INPUT -s 192.168.0.0/16 -j DROP

    SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -n1)
    [[ -z "$SSH_PORT" ]] && SSH_PORT=22
    log "[i] Detected SSH Port: $SSH_PORT"

    iptables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW \
    -m limit --limit 8/min --limit-burst 20 -j ACCEPT

    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT

    iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    iptables -A INPUT -f -j DROP
    iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 200 -j ACCEPT

    iptables -A INPUT -p icmp --icmp-type echo-request -m limit \
    --limit 30/sec --limit-burst 30 -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type parameter-problem -j ACCEPT

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT

  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6
  netfilter-persistent save >> "$LOGFILE" 2>&1

  log "[✓] iptables installed."
}

# ========================================
# INSTALL IPTABLES IPv6
# ========================================
install_iptables_ipv6() {
  log ">>> [ip6tables] Installing iptables IPv6 rules..."

  ip6tables -F
  ip6tables -X
  ip6tables -Z

  ip6tables -A INPUT -i lo -j ACCEPT
  ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -n1)
  [[ -z "$SSH_PORT" ]] && SSH_PORT=22

  ip6tables -A INPUT -p tcp --dport "$SSH_PORT" -m state --state NEW \
    -m limit --limit 8/min --limit-burst 20 -j ACCEPT

  ip6tables -A INPUT -p tcp --dport 9090 -m state --state NEW \
    -m limit --limit 8/min --limit-burst 20 -j ACCEPT    
  ip6tables -A INPUT -p tcp --dport 80  -j ACCEPT
  ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
  ip6tables -A INPUT -p ipv6-icmp -j ACCEPT
  ip6tables -A INPUT -m conntrack --ctstate INVALID -j DROP

  ip6tables -P INPUT DROP
  ip6tables -P FORWARD DROP
  ip6tables -P OUTPUT ACCEPT

  ip6tables-save > /etc/iptables/rules.v6
  netfilter-persistent save >> "$LOGFILE" 2>&1

  log "[✓] iptables IPv6 installed."
}

# ========================================
# INSTALL NGINX BADBOT
# ========================================
install_ngxbadbot() {
  log ">>> [BadBot] Installing NGINX Bad Bot Blocker..."

  local base_url="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master"
  local -A files=(
    ["conf.d/globalblacklist.conf"]="/etc/nginx/conf.d/globalblacklist.conf"
    ["conf.d/botblocker-nginx-settings.conf"]="/etc/nginx/conf.d/botblocker-nginx-settings.conf"
    ["bots.d/blockbots.conf"]="/etc/nginx/bots.d/blockbots.conf"
    ["bots.d/ddos.conf"]="/etc/nginx/bots.d/ddos.conf"
    ["bots.d/whitelist-ips.conf"]="/etc/nginx/bots.d/whitelist-ips.conf"
    ["bots.d/whitelist-domains.conf"]="/etc/nginx/bots.d/whitelist-domains.conf"
    ["bots.d/blacklist-user-agents.conf"]="/etc/nginx/bots.d/blacklist-user-agents.conf"
    ["bots.d/custom-bad-referrers.conf"]="/etc/nginx/bots.d/custom-bad-referrers.conf"
    ["bots.d/blacklist-ips.conf"]="/etc/nginx/bots.d/blacklist-ips.conf"
    ["bots.d/bad-referrer-words.conf"]="/etc/nginx/bots.d/bad-referrer-words.conf"
  )

  mkdir -p /etc/nginx/conf.d /etc/nginx/bots.d

  local success=true
  local failed_files=()

  for path in "${!files[@]}"; do
    local url="$base_url/$path"
    local output="${files[$path]}"
    logv "[WGET] $(basename "$output") from $url"
    if wget -q "$url" -O "$output" 2>> "$LOGFILE"; then
      logv "[✓] $(basename "$output")"
    else
      failed_files+=("$(basename "$output")")
      success=false
    fi
  done
  
  touch /etc/nginx/includes/badbot.conf
  if $success; then
    if ! grep -q "blockbots.conf" /etc/nginx/includes/badbot.conf; then
      echo 'include /etc/nginx/bots.d/blockbots.conf;' >> /etc/nginx/includes/badbot.conf
    fi
    if ! grep -q "ddos.conf" /etc/nginx/includes/badbot.conf; then
      echo 'include /etc/nginx/bots.d/ddos.conf;' >> /etc/nginx/includes/badbot.conf
    fi

    systemctl reload nginx >> "$LOGFILE" 2>&1
    log "[✓] Bad Bot Blocker installed."
  else
    log "[!] Bad Bot Blocker: gagal download: ${failed_files[*]}"
  fi
}

# ========================================
# INSTALL REDIS
# ========================================
install_redis() {
  log ">>> [Redis] Installing Redis..."

  apt-get update >> "$LOGFILE" 2>&1
  apt-get install -y redis-server >> "$LOGFILE" 2>&1
  
  if ! command -v redis-server >/dev/null; then
    log "[x] Redis installation failed."
    return 1
  fi

  if [[ -f /etc/redis/redis.conf ]]; then
    cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
  fi

  if ! mycurl "$REMOTE_CONF_BASE/redis/redis.conf" -o /etc/redis/redis.conf; then
    log "[x] Redis config download failed! Restoring backup..."
    [[ -f /etc/redis/redis.conf.bak ]] && cp /etc/redis/redis.conf.bak /etc/redis/redis.conf
    return 1
  fi

  usermod -aG redis www-data
  log "[✓] www-data added to redis group (socket access)"

  mkdir -p /run/redis
  chown redis:redis /run/redis
  chmod 755 /run/redis

  systemctl enable redis-server >> "$LOGFILE" 2>&1
  systemctl restart redis-server >> "$LOGFILE" 2>&1

  if systemctl is-active --quiet redis-server; then
    log "[✓] Redis installed & running (unix socket: /run/redis/redis.sock)"
  else
    log "[x] Redis failed to start! Check: journalctl -u redis-server"
    return 1
  fi

  if [[ -S /run/redis/redis.sock ]]; then
    log "[✓] Redis socket active: /run/redis/redis.sock"
  else
    log "[!] Redis running but socket not found. Check redis.conf unixsocket directive."
  fi
}

# ========================================
# INSTALL AUTO WAF UPDATE CRON
# ========================================
install_waf_auto_update() {
  log ">>> [WAF] Installing auto-update script..."

  local TARGET="/usr/local/bin/waf-update.sh"

    if mycurl "$REMOTE_CONF_BASE/bin/waf-update.sh" -o "$TARGET"; then
        chmod +x "$TARGET"
        log "WAF update script installed at: $TARGET"
    else
        log "[x] Failed to download waf-update.sh"
        return 1
    fi

  if ! crontab -l 2>/dev/null | grep -q "waf-update.sh"; then
    ( crontab -l 2>/dev/null; echo "0 2 * * * /usr/local/bin/waf-update.sh >/dev/null 2>&1" ) | crontab -
    log "[✓] Cronjob added: update WAF every night at 02:00"
  else
    log "[i] Cronjob already exists, skipping"
  fi

  log ">>> [WAF] Update WAF..."
  bash /usr/local/bin/waf-update.sh >> "$LOGFILE" 2>&1
}

# ========================================
# INSTALL FILEMANAGER
# ========================================
install_filemanager() {
  log "[FB] Installing Filebrowser..."

  if ! command -v filebrowser >/dev/null 2>&1; then
    curl -fsSL https://raw.githubusercontent.com/filebrowser/get/master/get.sh | bash >> "$LOGFILE" 2>&1
    log "[FB] Filebrowser binary installed."
  else
    log "[FB] Filebrowser already installed, skipping."
  fi

  systemctl stop filebrowser 2>/dev/null || true

  mkdir -p /etc/filebrowser
  mkdir -p /var/lib/filebrowser
  chown -R root:root /var/lib/filebrowser

  FB_ADMIN_USER="admin"
  FB_ADMIN_PASS=$(cat /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)

  cat > /root/.filebrowser_admin <<EOF
{
  "username": "admin",
  "password": "$FB_ADMIN_PASS"
}
EOF
  chmod 600 /root/.filebrowser_admin
  log "[FB] Admin credentials saved → /root/.filebrowser_admin"

  cat > /etc/filebrowser/config.json <<EOF
{
  "port": 2222,
  "address": "127.0.0.1",
  "log": "stdout",
  "database": "/var/lib/filebrowser/database.db",
  "root": "/home",
  "baseURL": "/fm",
  "authMethod": "default",
  "database-wal": true,
  "lockTimeout": 30
}
EOF

  log "[FB] Config written → /etc/filebrowser/config.json"

  rm -f /var/lib/filebrowser/database.db

  filebrowser config init \
      --config /etc/filebrowser/config.json >> "$LOGFILE" 2>&1

  filebrowser --config /etc/filebrowser/config.json \
  users add "$FB_ADMIN_USER" "$FB_ADMIN_PASS" --perm.admin=true >> "$LOGFILE" 2>&1

  cat > /etc/systemd/system/filebrowser.service <<EOF
[Unit]
Description=Filebrowser File Manager
After=network.target

[Service]
User=root
ExecStart=/usr/local/bin/filebrowser --config /etc/filebrowser/config.json --tokenExpirationTime 999999h
Restart=always

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable filebrowser >> "$LOGFILE" 2>&1
  systemctl restart filebrowser >> "$LOGFILE" 2>&1

  sleep 1
  log "[FB] Waiting for Filebrowser to boot..."

  TOKEN=$(curl -s -X POST http://127.0.0.1:2222/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"$FB_ADMIN_USER\",\"password\":\"$FB_ADMIN_PASS\"}")

  if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
    log "[FB] ERROR: Failed to acquire token!"
    return 1
  fi

  echo "$TOKEN" > /root/.filebrowser_token
  chmod 600 /root/.filebrowser_token

  log "[FB] Token saved → /root/.filebrowser_token"
}

# ========================================
# INSTALL WPCLI
# ========================================
install_wpcli() {
    log "[+] Downloading WP-CLI..."
    curl -fsSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
      -o /usr/local/bin/wp 2>> "$LOGFILE"
    chmod +x /usr/local/bin/wp
    log "[✓] WP-CLI installed."
}

disable_impact_service(){
systemctl disable --now apt-daily.timer
systemctl disable --now apt-daily-upgrade.timer
systemctl disable --now unattended-upgrades
systemctl disable --now man-db.timer
systemctl disable --now fwupd-refresh.timer
systemctl disable --now motd-news.timer
systemctl disable --now update-notifier-download.timer
systemctl disable --now update-notifier-motd.timer
}

summary_installation() {
  local C="\033[36m"  # cyan
  local G="\033[32m"  # green
  local R="\033[31m"  # red
  local Y="\033[33m"  # yellow
  local B="\033[1m"   # bold
  local N="\033[0m"   # reset

  local SERVER_IP
  SERVER_IP=$(hostname -I | awk '{print $1}')

  echo ""
  echo -e "${B}╔═══════════════════════════════════════════════════════╗${N}"
  echo -e "${B}║            INSTALLATION COMPLETE                      ║${N}"
  echo -e "${B}╚═══════════════════════════════════════════════════════╝${N}"
  echo ""
  echo -e "  ${C}Server${N}     : $SERVER_IP"
  echo -e "  ${C}OS${N}         : Ubuntu $OS_VERSION ($CODENAME)"
  echo -e "  ${C}Date${N}       : $(date '+%Y-%m-%d %H:%M:%S')"
  echo -e "  ${C}Log${N}        : $LOGFILE"
  echo ""
  echo -e "${B}─── Services ───────────────────────────────────────────${N}"

  # NGINX
  if command -v nginx >/dev/null 2>&1; then
    local nginx_ver
    nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}')
    echo -e "  ${G}✓${N} NGINX        : $nginx_ver ($(systemctl is-active nginx))"
  else
    echo -e "  ${R}✗${N} NGINX        : not installed"
  fi

  # PHP
  if command -v php${PHP_VERSION} >/dev/null 2>&1; then
    local php_ver
    php_ver=$(php${PHP_VERSION} -r 'echo PHP_VERSION;' 2>/dev/null)
    echo -e "  ${G}✓${N} PHP-FPM      : $php_ver ($(systemctl is-active php${PHP_VERSION}-fpm))"
  else
    echo -e "  ${R}✗${N} PHP-FPM      : not installed"
  fi

  # MariaDB
  if command -v mariadb >/dev/null 2>&1; then
    local maria_ver
    maria_ver=$(mariadb --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo -e "  ${G}✓${N} MariaDB      : $maria_ver ($(systemctl is-active mariadb))"
  else
    echo -e "  ${R}✗${N} MariaDB      : not installed"
  fi

  # Redis
  if command -v redis-server >/dev/null 2>&1; then
    local redis_ver
    redis_ver=$(redis-server --version 2>/dev/null | grep -oP '\d+\.\d+\.\d+' | head -1)
    echo -e "  ${G}✓${N} Redis        : $redis_ver ($(systemctl is-active redis-server))"
  else
    echo -e "  ${R}✗${N} Redis        : not installed"
  fi

  # Fail2Ban
  if command -v fail2ban-server >/dev/null 2>&1; then
    echo -e "  ${G}✓${N} Fail2Ban     : $(systemctl is-active fail2ban)"
  else
    echo -e "  ${R}✗${N} Fail2Ban     : not installed"
  fi

  # Filebrowser
  if systemctl is-active --quiet filebrowser 2>/dev/null; then
    echo -e "  ${G}✓${N} Filebrowser  : running"
  else
    echo -e "  ${R}✗${N} Filebrowser  : not running"
  fi

  echo ""
  echo -e "${B}─── Swap & Kernel ──────────────────────────────────────${N}"

  # Swap
  if swapon --show | grep -q "$SWAPFILE"; then
    local swp_size
    swp_size=$(swapon --show --bytes | awk 'NR==2{printf "%.0f MB", $3/1024/1024}')
    echo -e "  ${G}✓${N} Swap         : $swp_size ($SWAPFILE)"
  else
    echo -e "  ${Y}─${N} Swap         : not enabled"
  fi

  # BBR
  local active_cc
  active_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)
  if [[ "$active_cc" == "bbr" ]]; then
    echo -e "  ${G}✓${N} TCP BBR      : enabled"
  else
    echo -e "  ${Y}─${N} TCP BBR      : $active_cc"
  fi

  echo ""
  echo -e "${B}─── Firewall ───────────────────────────────────────────${N}"

  if command -v iptables >/dev/null 2>&1; then
    local ssh_port
    ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | awk -F: '{print $NF}' | head -n1)
    [[ -z "$ssh_port" ]] && ssh_port=22
    echo -e "  ${G}✓${N} iptables     : active (INPUT=DROP)"
    echo -e "    Allowed      : SSH(:$ssh_port) HTTP(:80) HTTPS(:443)"
    echo -e "    Rules saved  : /etc/iptables/rules.v4, rules.v6"
  else
    echo -e "  ${Y}─${N} iptables     : not configured"
  fi

  echo ""
  echo -e "${B}─── Access Info ────────────────────────────────────────${N}"

  # phpMyAdmin
  if [[ -d /usr/share/phpmyadmin ]]; then
    echo -e "  ${C}phpMyAdmin${N}   : http://$SERVER_IP/pma"
  fi

  # Filebrowser
  if [[ -f /root/.filebrowser_admin ]]; then
    local fb_user fb_pass
    fb_user=$(jq -r '.username' /root/.filebrowser_admin 2>/dev/null)
    fb_pass=$(jq -r '.password' /root/.filebrowser_admin 2>/dev/null)
    echo -e "  ${C}Filebrowser${N}  : http://$SERVER_IP/fm"
    echo -e "    User         : $fb_user"
    echo -e "    Password     : $fb_pass"
  fi

  # MariaDB root
  if [[ -f /root/.mysql_root_password ]]; then
    echo -e "  ${C}MariaDB root${N} : saved → /root/.mysql_root_password"
  fi

  echo ""
  echo -e "${B}─── Config Paths ───────────────────────────────────────${N}"
  echo -e "  NGINX      : /etc/nginx/"
  echo -e "  PHP        : /etc/php/$PHP_VERSION/"
  echo -e "  MariaDB    : /etc/mysql/mariadb.conf.d/"
  echo -e "  Redis      : /etc/redis/redis.conf"
  echo -e "  Fail2Ban   : /etc/fail2ban/"
  echo ""
  echo -e "${B}═════════════════════════════════════════════════════════${N}"
  echo ""
}

# ========================================
# MAIN
# ========================================
check_root
install_dependencies
add_swap
install_sysctl
enable_bbr
install_nginx
install_php
install_ioncube
install_mariadb
install_phpmyadmin
install_fail2ban
install_iptables
install_iptables_ipv6
install_ngxbadbot
install_redis
install_waf_auto_update
install_filemanager
install_wpcli
disable_impact_service
summary_installation
