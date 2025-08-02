#!/bin/bash

REMOTE_CONF_BASE="https://vps.fio.link/conf"
PHP_VERSION="8.3"
SWAPFILE="/swapfile"
SWAPSIZE="2G"
LOGFILE="/var/log/installer.log"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
MARIADB_VERSION="11.4"

mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"

log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $@" | tee -a "$LOGFILE"
}

mycurl() {
  curl -fsSL -A "$CURL_UA" "$@"
}

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

install_dependencies(){
  log "[+] Installing dependencies..."
  apt-get install -y software-properties-common curl dirmngr gnupg ca-certificates lsb-release
}

add_swap() {
  if swapon --show | grep -q "$SWAPFILE"; then
    log "[i] Swapfile already exists. Skipping swap creation."
    return
  fi
  log "[+] Creating $SWAPSIZE swapfile..."
  fallocate -l $SWAPSIZE $SWAPFILE
  chmod 600 $SWAPFILE
  mkswap $SWAPFILE
  swapon $SWAPFILE
  echo "$SWAPFILE none swap sw 0 0" >> /etc/fstab
  log "[✓] Swapfile created and enabled."
}

install_nginx() {
  log ">>> [NGINX] Installing NGINX for Ubuntu $OS_VERSION ($CODENAME)..."
  is_supported_os || fail_unsupported_os
  log ">>> [NGINX] Adding PPA from Ondřej Surý..."
  mycurl "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x4F4EA0AAE5267A6C" \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/ondrej-archive.gpg
  add-apt-repository -y "deb https://ppa.launchpadcontent.net/ondrej/nginx/ubuntu $CODENAME main"
  add-apt-repository -y "deb-src https://ppa.launchpadcontent.net/ondrej/nginx/ubuntu $CODENAME main"
  apt-get update
  log ">>> [NGINX] Installing nginx and essential modules..."
  apt-get install -y nginx nginx-full libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter
  log ">>> [NGINX] Fetching remote NGINX configuration from $REMOTE_CONF_BASE..."
  mkdir -p /etc/nginx/sites-enabled
  mkdir -p /etc/nginx/sites-available
  mkdir -p /etc/nginx/conf.d
  mycurl "$REMOTE_CONF_BASE/nginx/nginx.conf" -o /etc/nginx/nginx.conf
  mycurl "$REMOTE_CONF_BASE/nginx/custom-vhost.conf" -o /etc/nginx/sites-available/custom-vhost.conf.example
  log ">>> [NGINX] Restarting NGINX..."
  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl enable nginx    
  systemctl restart nginx
  log ">>> [NGINX] Installation complete."
}

install_php() {
  log ">>> [PHP] Installing PHP for Ubuntu $OS_VERSION ($CODENAME)..."
  is_supported_os || fail_unsupported_os
  log ">>> [PHP] Adding Ondřej PHP PPA..."
  mycurl "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x4F4EA0AAE5267A6C" \
    | gpg --dearmor -o /etc/apt/trusted.gpg.d/ondrej-php.gpg
  add-apt-repository -y "deb https://ppa.launchpadcontent.net/ondrej/php/ubuntu $CODENAME main"
  add-apt-repository -y "deb-src https://ppa.launchpadcontent.net/ondrej/php/ubuntu $CODENAME main"
  apt-get update
  log ">>> [PHP] Installing PHP and common extensions..."
  apt-get install -y php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-cli \
    php$PHP_VERSION-mysql php$PHP_VERSION-curl php$PHP_VERSION-mbstring \
    php$PHP_VERSION-xml php$PHP_VERSION-gd php$PHP_VERSION-zip php$PHP_VERSION-bcmath
  log ">>> [PHP] Fetching PHP-FPM config from $REMOTE_CONF_BASE..."
  mkdir -p /etc/php/$PHP_VERSION/fpm/conf.d
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/php.ini" -o /etc/php/$PHP_VERSION/fpm/php.ini
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/www.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/global.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/global.conf
  mycurl "$REMOTE_CONF_BASE/php/$PHP_VERSION/pool.d/custom.conf" -o /etc/php/$PHP_VERSION/fpm/pool.d/custom.example
  log ">>> [PHP] Restarting PHP-FPM..."
  systemctl restart php$PHP_VERSION-fpm
  systemctl enable php$PHP_VERSION-fpm
  systemctl daemon-reload
  log ">>> [PHP] Installation complete."
}

install_mariadb() {
  log ">>> [MariaDB] Installing MariaDB $MARIADB_VERSION for Ubuntu $OS_VERSION ($CODENAME)..."
  is_supported_os || fail_unsupported_os
  log "[+] Adding MariaDB GPG key..."
  curl -fsSL https://mariadb.org/mariadb_release_signing_key.asc \
    | gpg --dearmor -o /usr/share/keyrings/mariadb-keyring.gpg
  log "[+] Adding MariaDB APT repository for version $MARIADB_VERSION..."
  echo "deb [signed-by=/usr/share/keyrings/mariadb-keyring.gpg] https://mirror.mariadb.org/repo/$MARIADB_VERSION/ubuntu $CODENAME main" \
    > /etc/apt/sources.list.d/mariadb.list
  log "[+] Updating apt and installing MariaDB..."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
  log "[+] Applying custom MariaDB config from $REMOTE_CONF_BASE..."
  rm -rf /etc/mysql/mariadb.conf.d/*
  curl -fsSL "$REMOTE_CONF_BASE/mariadb/stack-my.cnf" -o /etc/mysql/mariadb.conf.d/99-stack.cnf
  cat > /etc/systemd/system/mariadb.service.d/limits.conf <<EOF
[Service]
LimitNOFILE=65535
Environment="MYSQLD_OPTS="
Environment="_WSREP_NEW_CLUSTER="
Environment="_WSREP_START_POSITION="
EOF
  systemctl daemon-reexec
  systemctl daemon-reload
  systemctl restart mariadb
  systemctl enable mariadb
  log "[✓] MariaDB $MARIADB_VERSION installed and started successfully."
  echo ">>> [MariaDB] Securing installation..."
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
  echo ">>> [✓] MariaDB secured. Root password saved to /root/.mysql_root_password"
}

install_fail2ban() {
  log ">>> [Fail2Ban] Installing and configuring Fail2Ban..."
  apt-get update
  apt-get install -y fail2ban
  cat >/etc/fail2ban/filter.d/wp-login.conf <<'EOF'
[Definition]
failregex = <HOST> -.*"(POST|GET) /wp-login.php
ignoreregex =
EOF
  cat >/etc/fail2ban/jail.d/wordpress.conf <<'EOF'
[wp-login]
enabled  = true
filter   = wp-login
action   = iptables[name=WPLogin, port=http, protocol=tcp]
logpath  = /home/*/logs/access.log
maxretry = 5
findtime = 600
bantime  = 3600
EOF
  cat >/etc/fail2ban/filter.d/mysqld-auth.conf <<'EOF'
[Definition]
failregex = ^.*Access denied for user .*@'<HOST>'.*$
ignoreregex =
EOF
  cat >/etc/fail2ban/jail.d/mariadb.conf <<'EOF'
[mariadb-auth]
enabled = true
filter  = mysqld-auth
port    = mysql
logpath = /var/log/mysql/error.log
maxretry = 5
bantime = 3600
EOF
  systemctl enable fail2ban
  systemctl restart fail2ban
  log "[✓] Fail2Ban installed and configured."
}

install_iptables() {
  log ">>> [iptables] Installing iptables and setting firewall rules..."
  apt-get update
  apt-get install -y iptables iptables-persistent
  iptables -F
  iptables -X
  iptables -Z
  iptables -P INPUT DROP
  iptables -P FORWARD DROP
  iptables -P OUTPUT ACCEPT
  iptables -A INPUT -i lo -j ACCEPT
  iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A INPUT -p tcp --dport 80 -j ACCEPT
  iptables -A INPUT -p tcp --dport 443 -j ACCEPT
  netfilter-persistent save -y
  iptables-save > /etc/iptables/rules.v4
  log "[✓] iptables installed, rules applied and saved."
}

check_root
install_dependencies
add_swap
install_nginx
install_php
install_mariadb
install_fail2ban
install_iptables
