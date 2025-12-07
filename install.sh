#!/bin/bash

# ========================================
# CONFIGURABLE VARIABLES
# ========================================
REMOTE_CONF_BASE="https://vps.fio.link/conf"
PHP_VERSION="8.3"
SWAPFILE="/swapfile"
SWAPSIZE="2G"
LOGFILE="/var/log/installer.log"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
MARIADB_VERSION="11.4"

# ========================================
# LOGGING + CURL WRAPPER
# ========================================
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"

log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $@" | tee -a "$LOGFILE"
}

mycurl() {
  if curl -fsSL --retry 3 --connect-timeout 5 -A "$CURL_UA" "$@"; then
    log "[✓] Download OK: $1"
  else
    log "[!] Download failed: $1"
    return 1
  fi
}

# ========================================
# OS DETECTION
# ========================================
source /etc/os-release
CODENAME=$VERSION_CODENAME
OS_VERSION=$VERSION_ID
SUPPORTED_OS=("22.04" "24.04")

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
  log "Only Ubuntu 22.04 (jammy) and 24.04 (noble) are supported."
  exit 1
}

# ========================================
# Dependencies INSTALLER
# ========================================
install_dependencies(){
  log "[+] Installing dependencies..."
  apt-get update -y >> "$LOGFILE" 2>&1
  apt-get install -y software-properties-common curl dirmngr gnupg ca-certificates \
    lsb-release certbot python3-certbot-nginx zip unzip tar >> "$LOGFILE" 2>&1
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
    log ">>> [i] Tuning sysctl"
    mycurl "$REMOTE_CONF_BASE/sysctl/99-tuning.conf" -o /etc/sysctl.d/99-tuning.conf
    sysctl -p
    log "[i] Success"
}

# ========================================
# INSTALL NGINX
# ========================================
install_nginx() {
  log ">>> [NGINX] Installing NGINX for Ubuntu $OS_VERSION ($CODENAME)..."
  is_supported_os || fail_unsupported_os

  log ">>> [NGINX] Adding PPA from Ondřej Surý..."

  mycurl "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x4F4EA0AAE5267A6C" \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/ondrej-archive.gpg

  add-apt-repository -y "deb https://ppa.launchpadcontent.net/ondrej/nginx/ubuntu $CODENAME main" >> "$LOGFILE" 2>&1
  add-apt-repository -y "deb-src https://ppa.launchpadcontent.net/ondrej/nginx/ubuntu $CODENAME main" >> "$LOGFILE" 2>&1
  apt-get update >> "$LOGFILE" 2>&1

  log ">>> [NGINX] Installing nginx..."
  apt-get install -y nginx nginx-full libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter >> "$LOGFILE" 2>&1

  log ">>> [NGINX] Fetching remote NGINX config..."
  mkdir -p /etc/nginx/{sites-enabled,sites-available,conf.d,includes} /var/cache/nginx/cache
  touch /etc/nginx/includes/{global.conf,be-proc-global.conf,fe-proc-global.conf}
  mkdir -p /etc/nginx/ssl

  openssl dhparam -dsaparam -out /etc/nginx/ssl/dhparams.pem 2048 >> "$LOGFILE" 2>&1
  chmod 600 /etc/nginx/ssl/dhparams.pem
  chown root:root /etc/nginx/ssl/dhparams.pem
  
  cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak 2>/dev/null
  mycurl "$REMOTE_CONF_BASE/nginx/nginx.conf" -o /etc/nginx/nginx.conf
  mycurl "$REMOTE_CONF_BASE/nginx/custom-vhost.conf" -o /etc/nginx/sites-available/custom-vhost.conf.example

  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/gzip.conf" -o /etc/nginx/conf.d/gzip.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/brotli.conf" -o /etc/nginx/conf.d/brotli.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/cloudflare.conf" -o /etc/nginx/conf.d/cloudflare.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/header-sec.conf" -o /etc/nginx/conf.d/header-sec.conf
  mycurl "$REMOTE_CONF_BASE/nginx/conf.d/wp-map.conf" -o /etc/nginx/conf.d/wp-map.conf
  mycurl "$REMOTE_CONF_BASE/nginx/mime.types" -o /etc/nginx/mime.types
  touch /etc/nginx/conf.d/botblocker-nginx-settings.conf
  touch /etc/nginx/conf.d/globalblacklist.conf
  mkdir -p /etc/nginx/bots.d
  touch /etc/nginx/bots.d/{bad-referrer-words.conf,blacklist-ips.conf,blacklist-user-agents.conf,blockbots.conf,custom-bad-referrers.conf,ddos.conf,whitelist-domains.conf,whitelist-ips.conf}

  mycurl "$REMOTE_CONF_BASE/nginx/includes/fe-proc-global.conf" -o /etc/nginx/includes/fe-proc-global.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/fe-proc-global.conf" -o /etc/nginx/includes/be-proc-global.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/security-rules.conf" -o /etc/nginx/includes/security-rules.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/static.conf" -o /etc/nginx/includes/static.conf
  mycurl "$REMOTE_CONF_BASE/nginx/includes/fastcgi.conf" -o /etc/nginx/includes/fastcgi.conf

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
  apt-get update >> "$LOGFILE" 2>&1

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
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/global.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/global.conf
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/custom.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/custom.example

  systemctl restart php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  systemctl enable php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  log ">>> [PHP] Installation complete."

  log ">>> [PHP] Applying OPcache performance settings..."

  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/conf.d/10-opcache.ini" -o /etc/php/$PHP_VERSION/fpm/conf.d/10-opcache.ini
  systemctl restart php$PHP_VERSION-fpm >> "$LOGFILE" 2>&1
  log "[✓] OPcache tuning applied → $opcache_file"
    
}

install_ioncube() {
  log ">>> [ionCube] Installing ionCube Loader for PHP $PHP_VERSION..."

  cd /tmp
  local IONCUBE_DOWNLOAD="https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"

  log "[+] Downloading ionCube Loader..."
  curl -sSL "$IONCUBE_DOWNLOAD" -o ioncube.tar.gz

  tar -xzf ioncube.tar.gz
  cd ioncube

  local PHP_API_DIR=$(php -i | grep "^extension_dir" | awk '{print $3}')
  local LOADER_FILE="ioncube_loader_lin_${PHP_VERSION}.so"

  if [[ ! -f "$LOADER_FILE" ]]; then
      fail "ionCube loader for PHP $PHP_VERSION not found! (ionCube belum support versi ini?)"
  fi

  log "[+] Installing ionCube loader → $PHP_API_DIR"
  cp "$LOADER_FILE" "$PHP_API_DIR"

  local INI_FILE="/etc/php/$PHP_VERSION/fpm/conf.d/00-ioncube.ini"
  echo "zend_extension=$PHP_API_DIR/$LOADER_FILE" > "$INI_FILE"

  echo "zend_extension=$PHP_API_DIR/$LOADER_FILE" \
      > /etc/php/$PHP_VERSION/cli/conf.d/00-ioncube.ini

  systemctl restart php$PHP_VERSION-fpm
  log "[✓] ionCube installed for PHP $PHP_VERSION"

  # Cleanup
  rm -rf /tmp/ioncube /tmp/ioncube.tar.gz
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
Environment="MYSQLD_OPTS="
Environment="_WSREP_NEW_CLUSTER="
Environment="_WSREP_START_POSITION="
EOF

  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl restart mariadb >> "$LOGFILE" 2>&1
  systemctl enable mariadb >> "$LOGFILE" 2>&1

  log "[✓] MariaDB installed."

  log ">>> Securing MariaDB..."
  MYSQL_ROOT_PASSWORD=$(openssl rand -base64 20)

  mysql -u root <<EOF
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
  cd "$TMP_DIR" || exit 1
  PMA_VER="5.2.1"

  mycurl "https://files.phpmyadmin.net/phpMyAdmin/${PMA_VER}/phpMyAdmin-${PMA_VER}-all-languages.zip" \
    -o pma.zip
  unzip -q pma.zip -d "$TMP_DIR"

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

  mycurl "$REMOTE_CONF_BASE/nginx/includes/phpmyadmin.conf" \
    -o /etc/nginx/includes/phpmyadmin.conf

  if ! grep -q "phpmyadmin.conf" /etc/nginx/includes/global.conf 2>/dev/null; then
    echo "include /etc/nginx/includes/phpmyadmin.conf;" >> /etc/nginx/includes/global.conf
  fi

  nginx -t >> "$LOGFILE" 2>&1 && systemctl reload nginx >> "$LOGFILE" 2>&1
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

  mycurl "$REMOTE_CONF_BASE/fail2ban/filter.d/phpmyadmin.conf" \
    -o /etc/fail2ban/filter.d/phpmyadmin.conf
  mycurl "$REMOTE_CONF_BASE/fail2ban/jail.d/phpmyadmin.conf" \
    -o /etc/fail2ban/jail.d/phpmyadmin.conf

  systemctl enable fail2ban >> "$LOGFILE" 2>&1
  systemctl restart fail2ban >> "$LOGFILE" 2>&1

  log "[✓] Fail2Ban installed."
  fail2ban-client -d || log "[!] Fail2Ban config broken"
}

# ========================================
# INSTALL IPTABLES
# ========================================
install_iptables() {
  log ">>> [iptables] Installing iptables..."

  echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
  echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections

  DEBIAN_FRONTEND=noninteractive apt-get install -y iptables iptables-persistent >> "$LOGFILE" 2>&1

  iptables -F
  iptables -X
  iptables -Z

  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT

  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT  

  iptables-save > /etc/iptables/rules.v4
  ip6tables-save > /etc/iptables/rules.v6

  log "[✓] iptables installed."
}

# ========================================
# INSTALL NGINX BADBOT
# ========================================
install_ngxbadbot() {
  echo ">>> [NGINX Bad Bot Blocker] Mengunduh konfigurasi..."

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

  for path in "${!files[@]}"; do
    local url="$base_url/$path"
    local output="${files[$path]}"
    echo -n "Mengunduh $(basename "$output")... "
    if wget -q "$url" -O "$output"; then
      echo "Berhasil."
    else
      echo "Gagal!"
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
    echo ">>> Semua file berhasil diunduh dan konfigurasi ditambahkan."
  else
    echo "!!! Beberapa file gagal diunduh."
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

  # Backup config
  if [[ -f /etc/redis/redis.conf ]]; then
    cp /etc/redis/redis.conf /etc/redis/redis.conf.bak
  fi

  mycurl "$REMOTE_CONF_BASE/redis/redis.conf" -o /etc/redis/redis.conf

  if ! redis-server /etc/redis/redis.conf --test-memory 4 >/dev/null 2>&1; then
    log "[x] Redis config test failed! Restoring backup..."
    cp /etc/redis/redis.conf.bak /etc/redis/redis.conf
    return 1
  fi

  systemctl enable redis-server >> "$LOGFILE" 2>&1
  systemctl restart redis-server >> "$LOGFILE" 2>&1

  if systemctl is-active --quiet redis-server; then
    log "[✓] Redis installed & running."
  else
    log "[x] Redis failed to start!"
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
}

# ========================================
# INSTALL FILEMANAGER
# ========================================
install_filemanager() {
    log "[i]"
}


summary_installation() {
  echo ""
  echo "====================================================="
  echo "                INSTALLATION SUMMARY"
  echo "====================================================="
  echo "OS          : Ubuntu $OS_VERSION ($CODENAME)"
  echo "Time        : $(date)"
  echo "Log File    : $LOGFILE"
  echo "-----------------------------------------------------"

  # SWAP
  if swapon --show | grep -q "$SWAPFILE"; then
    swp_size=$(swapon --show --bytes | awk 'NR==2{printf "%.0f MB", $3/1024/1024}')
    echo "[Swap]      : ENABLED ($swp_size) → $SWAPFILE"
  else
    echo "[Swap]      : Not enabled"
  fi

  # NGINX
  if command -v nginx >/dev/null; then
    nginx_ver=$(nginx -v 2>&1 | awk -F/ '{print $2}')
    nginx_state=$(systemctl is-active nginx)
    echo "[NGINX]     : $nginx_ver | status: $nginx_state"
    echo "              conf: /etc/nginx/nginx.conf"
    echo "              vhosts: /etc/nginx/sites-available"
  else
    echo "[NGINX]     : NOT INSTALLED"
  fi

  # PHP
  if command -v php$PHP_VERSION >/dev/null; then
    php_ver=$(php$PHP_VERSION -v | head -n1)
    fpm_state=$(systemctl is-active php$PHP_VERSION-fpm)
    echo "[PHP]       : $php_ver | fpm: $fpm_state"
    echo "              ini: /etc/php/$PHP_VERSION/fpm/php.ini"
    echo "              pools: /etc/php/$PHP_VERSION/fpm/pool.d/"
  else
    echo "[PHP]       : NOT INSTALLED"
  fi

  # MariaDB
  if command -v mariadb >/dev/null || command -v mysql >/dev/null; then
    mariadb_ver=$(mariadb --version 2>/dev/null || mysql --version 2>/dev/null)
    mariadb_state=$(systemctl is-active mariadb)
    echo "[MariaDB]   : $mariadb_ver | status: $mariadb_state"
    echo "              root password → /root/.mysql_root_password"
  else
    echo "[MariaDB]   : NOT INSTALLED"
  fi

  # phpMyAdmin
  if [[ -d /usr/share/phpmyadmin ]]; then
    echo "[phpMyAdmin]: Installed → /pma"
  else
    echo "[phpMyAdmin]: NOT INSTALLED"
  fi

  # Fail2Ban
  if command -v fail2ban-server >/dev/null; then
    f2b_state=$(systemctl is-active fail2ban)
    echo "[Fail2Ban]  : Installed | status: $f2b_state"
  else
    echo "[Fail2Ban]  : NOT INSTALLED"
  fi

  # IPTABLES
  if command -v iptables >/dev/null; then
    default_policy=$(iptables -S | head -n3 | sed 's/-P //g')
    echo "[Firewall]  : iptables enabled"
    echo "              policies: $default_policy"
    echo "              allowed: SSH(22), HTTP(80), HTTPS(443)"
    echo "              saved: /etc/iptables/rules.v4"
  else
    echo "[Firewall]  : NOT INSTALLED"
  fi

  echo "-----------------------------------------------------"
  echo "Server IP   : $(hostname -I | awk '{print $1}')"
  echo "Docs        : nginx (/etc/nginx), php (/etc/php), DB (/etc/mysql)"
  echo "====================================================="
  echo ""
}

# ========================================
# MAIN
# ========================================
check_root
install_dependencies
add_swap
install_sysctl
install_nginx
install_php
install_ioncube
install_mariadb
install_phpmyadmin
install_fail2ban
install_iptables
install_ngxbadbot
install_redis
install_waf_auto_update
install_filemanager
summary_installation
