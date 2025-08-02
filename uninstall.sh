#!/bin/bash

PHP_VERSION="8.3"
MARIADB_VERSION="11.4"
LOGFILE="/var/log/uninstaller.log"
ONDREJ_KEY_ID="0x4F4EA0AAE5267A6C"

mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"

log() {
  echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $@" | tee -a "$LOGFILE"
}

prompt_confirm() {
  while true; do
    read -rp "$1 [y/n]: " yn
    case $yn in
      [Yy]*) return 0 ;;
      [Nn]*) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

uninstall_nginx() {
  log ">>> [NGINX] Stopping and uninstalling NGINX..."
  systemctl stop nginx
  systemctl disable nginx
  apt-get purge -y nginx-full libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter nginx

  if prompt_confirm "❓ Remove NGINX configuration in /etc/nginx?"; then
    rm -rf /etc/nginx
    log "[✓] Directory /etc/nginx has been removed."
  else
    log "[i] NGINX configuration kept."
  fi

  log ">>> [NGINX] Removing Ondřej PPA and key..."
  add-apt-repository -r -y "ppa:ondrej/nginx"
  rm -f /etc/apt/trusted.gpg.d/ondrej-archive.gpg

  log "[✓] NGINX and PPA have been removed."
}

uninstall_php() {
  log ">>> [PHP] Stopping and uninstalling PHP $PHP_VERSION..."
  systemctl stop php$PHP_VERSION-fpm
  systemctl disable php$PHP_VERSION-fpm
  apt-get purge -y "php$PHP_VERSION*" php-common

  if prompt_confirm "❓ Remove PHP configuration in /etc/php/$PHP_VERSION?"; then
    rm -rf /etc/php/$PHP_VERSION
    log "[✓] Directory /etc/php/$PHP_VERSION has been removed."
  else
    log "[i] PHP configuration kept."
  fi

  log ">>> [PHP] Removing Ondřej PPA and key..."
  add-apt-repository -r -y "ppa:ondrej/php"
  rm -f /etc/apt/trusted.gpg.d/ondrej-php.gpg

  log "[✓] PHP and PPA have been removed."
}

uninstall_mariadb() {
  log ">>> [MariaDB] Stopping and uninstalling MariaDB $MARIADB_VERSION..."
  systemctl stop mariadb
  systemctl disable mariadb
  apt-get purge -y mariadb-server mariadb-client mariadb-common

  if prompt_confirm "❓ Remove all MariaDB data and configuration (including /var/lib/mysql, /etc/mysql, /opt/mysql)?"; then
    rm -rf /var/lib/mysql /etc/mysql /opt/mysql
    log "[✓] MariaDB data and configuration have been removed."
  else
    log "[i] MariaDB data and configuration kept."
  fi

  if [ -f /root/.mysql_root_password ]; then
    if prompt_confirm "❓ Remove MariaDB root password file at /root/.mysql_root_password?"; then
      rm -f /root/.mysql_root_password
      log "[✓] Root password file has been removed."
    fi
  fi

  log ">>> [MariaDB] Removing MariaDB repository and key..."
  rm -f /etc/apt/sources.list.d/mariadb.list
  rm -f /usr/share/keyrings/mariadb-keyring.gpg

  log "[✓] MariaDB and its repository have been removed."
}

echo "========== LEMP STACK UNINSTALLER =========="
echo "Select component to uninstall:"
echo "1) NGINX"
echo "2) PHP"
echo "3) MariaDB"
echo "4) ALL"
echo "0) Exit"
read -rp "Enter your choice [0-4]: " pilihan

case "$pilihan" in
  1) uninstall_nginx ;;
  2) uninstall_php ;;
  3) uninstall_mariadb ;;
  4)
    uninstall_nginx
    uninstall_php
    uninstall_mariadb
    ;;
  0)
    echo "Aborted. Nothing was removed."
    exit 0
    ;;
  *)
    echo "[!] Invalid selection."
    exit 1
    ;;
esac

log ">>> Uninstallation completed."
