#!/bin/bash
set -e

LOGFILE="/var/log/uninstaller.log"
PHP_VERSION="${PHP_VERSION:-8.3}"
SWAPFILE="${SWAPFILE:-/swapfile}"

mkdir -p "$(dirname "$LOGFILE")"
: > "$LOGFILE"

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

logv() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"; }

confirm() {
  read -rp "$1 [y/n] (default: $2): " yn
  yn="${yn:-$2}"
  [[ "$yn" =~ ^[Yy]$ ]]
}

safe_rm() { [[ -n "${1:-}" && "$1" != "/" ]] && rm -rf --one-file-system "$1" 2>/dev/null || true; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

svc_stop_disable() {
  logv "[SVC] stop+disable $1"
  systemctl stop "$1" >> "$LOGFILE" 2>&1 || true
  systemctl disable "$1" >> "$LOGFILE" 2>&1 || true
}

apt_purge_if_installed() {
  local pkgs=("$@")
  local installed=()
  for p in "${pkgs[@]}"; do
    dpkg -l "$p" 2>/dev/null | awk '/^ii/{print $2}' | grep -qx "$p" && installed+=("$p")
  done
  if [[ ${#installed[@]} -gt 0 ]]; then
    logv "[PURGE] ${installed[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get purge -y "${installed[@]}" >> "$LOGFILE" 2>&1
  fi
}

remove_line() { sed -i "\|$2|d" "$1" 2>/dev/null || true; }

STEP_STATUS=()
run_step() {
  log "[RUN] $1"
  if "$2"; then STEP_STATUS+=("$1: OK"); else STEP_STATUS+=("$1: FAILED"); fi
}

# ---------------------------------------------------
# COMPONENTS
# ---------------------------------------------------

uninstall_nginx() {
  svc_stop_disable nginx
  apt_purge_if_installed nginx nginx-full nginx-core nginx-common \
    libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter

  safe_rm /etc/nginx
  safe_rm /var/cache/nginx
  safe_rm /var/log/nginx
  safe_rm /etc/apt/sources.list.d/nginx.list
  safe_rm /usr/share/keyrings/nginx-archive-keyring.gpg
  safe_rm /etc/apt/preferences.d/99-nginx

  sed -i '/ondrej\/nginx/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
  sed -i '/nginx\.org/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true

  userdel nginx 2>/dev/null || true
  groupdel nginx 2>/dev/null || true
}

uninstall_php() {
  svc_stop_disable php${PHP_VERSION}-fpm

  apt_purge_if_installed \
    php${PHP_VERSION} php${PHP_VERSION}-fpm php${PHP_VERSION}-cli php${PHP_VERSION}-common \
    php${PHP_VERSION}-mysql php${PHP_VERSION}-curl php${PHP_VERSION}-mbstring \
    php${PHP_VERSION}-xml php${PHP_VERSION}-gd php${PHP_VERSION}-zip \
    php${PHP_VERSION}-bcmath php${PHP_VERSION}-redis php${PHP_VERSION}-opcache \
    php${PHP_VERSION}-intl php-common

  safe_rm /etc/php/${PHP_VERSION}
  safe_rm /etc/php
  safe_rm /run/php

  local PHP_EXT_DIR
  PHP_EXT_DIR=$(php -i 2>/dev/null | grep "^extension_dir" | awk '{print $3}' || true)
  if [[ -n "$PHP_EXT_DIR" ]]; then
    rm -f "$PHP_EXT_DIR/ioncube_loader_lin_${PHP_VERSION}.so" 2>/dev/null || true
  fi

  add-apt-repository -r -y ppa:ondrej/php 2>/dev/null || true
  safe_rm /etc/apt/trusted.gpg.d/ondrej-php.gpg
  sed -i '/ondrej\/php/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
}

uninstall_mariadb() {
  svc_stop_disable mariadb
  svc_stop_disable mysql

  apt_purge_if_installed mariadb-server mariadb-client mariadb-common galera-* libmariadb* mariadb-*

  safe_rm /var/lib/mysql
  safe_rm /etc/mysql
  safe_rm /opt/mysql
  safe_rm /root/.mysql_root_password

  safe_rm /etc/apt/sources.list.d/mariadb.list
  safe_rm /usr/share/keyrings/mariadb-keyring.gpg
}

uninstall_phpmyadmin() {
  safe_rm /usr/share/phpmyadmin
  safe_rm /tmp/phpmyadmin
  safe_rm /etc/nginx/includes/phpmyadmin.conf
  safe_rm /etc/nginx/includes/filemanager.conf
  remove_line /etc/nginx/includes/global.conf 'phpmyadmin'
  remove_line /etc/nginx/includes/global.conf 'filemanager'

  if has_cmd mysql && systemctl is-active --quiet mariadb 2>/dev/null; then
    local MYSQL_PW
    MYSQL_PW=$(cat /root/.mysql_root_password 2>/dev/null || true)
    if [[ -n "$MYSQL_PW" ]]; then
      mysql -u root -p"$MYSQL_PW" -e "DROP DATABASE IF EXISTS phpmyadmin;" 2>/dev/null || true
    fi
  fi
}

uninstall_fail2ban() {
  svc_stop_disable fail2ban
  apt_purge_if_installed fail2ban
  safe_rm /etc/fail2ban
}

uninstall_iptables() {
  if has_cmd iptables; then
    iptables -F || true
    iptables -X || true
    iptables -Z || true
    iptables -P INPUT ACCEPT || true
    iptables -P FORWARD ACCEPT || true
    iptables -P OUTPUT ACCEPT || true
  fi

  if has_cmd ip6tables; then
    ip6tables -F || true
    ip6tables -X || true
    ip6tables -Z || true
    ip6tables -P INPUT ACCEPT || true
    ip6tables -P FORWARD ACCEPT || true
    ip6tables -P OUTPUT ACCEPT || true
  fi

  safe_rm /etc/iptables/rules.v4
  safe_rm /etc/iptables/rules.v6

  apt_purge_if_installed iptables-persistent netfilter-persistent
}

uninstall_badbot() {
  safe_rm /etc/nginx/bots.d
  safe_rm /etc/nginx/conf.d/globalblacklist.conf
  remove_line /etc/nginx/includes/global.conf 'bots.d'
}

uninstall_certbot() {
  apt_purge_if_installed certbot python3-certbot-nginx
  safe_rm /etc/letsencrypt
}

uninstall_redis() {
  svc_stop_disable redis-server
  apt_purge_if_installed redis-server redis-tools

  safe_rm /etc/redis
  safe_rm /var/lib/redis
  safe_rm /var/log/redis
  safe_rm /var/run/redis
}

uninstall_filemanager() {

  log "[FB] Uninstalling Filebrowser..."

  FB_SERVICE="/etc/systemd/system/filebrowser.service"
  FB_CONFIG="/etc/filebrowser/config.json"
  FB_DB="/var/lib/filebrowser/database.db"
  FB_DIR="/etc/filebrowser"
  FB_BIN="/usr/local/bin/filebrowser"
  FB_TOKEN="/root/.filebrowser_token"
  FB_ADMIN="/root/.filebrowser_admin"

  if systemctl is-active --quiet filebrowser; then
    systemctl stop filebrowser
  fi

  systemctl disable filebrowser 2>/dev/null || true

  rm -f "$FB_SERVICE"
  systemctl daemon-reload

  rm -f "$FB_CONFIG" "$FB_DB"
  rm -rf "$FB_DIR"
  rm -rf /var/lib/filebrowser
  rm -f "$FB_BIN"
  rm -f "$FB_TOKEN"
  rm -f "$FB_ADMIN"

  log "[FB] Filebrowser fully removed."
}


# ---------------------------------------------------
# REMOVE ALL HOSTING SITES (USER HOME, VHOST, POOLS)
# ---------------------------------------------------

uninstall_all_sites() {
  log "Removing managed hosting sites..."

  local managed_users
  managed_users=$(grep -h "root /home/" /etc/nginx/sites-available/*.conf 2>/dev/null | awk '{print $3}' | cut -d/ -f3 | sort -u || true)

  for d in /home/*; do
    [[ ! -d "$d" ]] && continue
    local user
    user=$(basename "$d")
    
    if [[ -f "$d/.php_version" ]] || echo "$managed_users" | grep -qx "$user"; then
       log "Removing managed user & files: $user"
       # Stop potential user processes
       pkill -u "$user" 2>/dev/null || true
       userdel -r "$user" 2>/dev/null || rm -rf "$d"
    else
       log "[i] Skipping non-managed user: $user"
    fi
  done

  find /etc/nginx/sites-available -type f -name "*-vhost.conf" -exec rm -f {} \;
  find /etc/nginx/sites-enabled   -type f -name "*-vhost.conf" -exec rm -f {} \;
  find /etc/nginx/includes -type f -name "filemanager-*.conf" -exec rm -f {} \;
  find /etc/php/*/fpm/pool.d/ -type f -name "*.conf" -exec rm -f {} \;
  find /etc/logrotate.d -type f -name "*.conf" -exec grep -q "/home/" {} \; -exec rm -f {} \; 2>/dev/null
  find /run/php -type s -name "php${PHP_VERSION}-fpm-*.sock" -exec rm -f {} \;

  safe_rm /usr/local/bin/wp
  safe_rm /etc/ssl/selfsigned

  systemctl restart php${PHP_VERSION}-fpm 2>/dev/null || true
  has_cmd nginx && nginx -t && systemctl reload nginx || true
}

uninstall_swap() {
  if [[ -f "$SWAPFILE" ]]; then
    swapoff "$SWAPFILE" 2>/dev/null || true
    safe_rm "$SWAPFILE"
    sed -i "\|$SWAPFILE none swap|d" /etc/fstab
  fi
}

uninstall_sysctl() {
  safe_rm /etc/sysctl.d/99-tuning.conf
  safe_rm /etc/sysctl.d/99-bbr-fq.conf
  sysctl --system >/dev/null 2>&1 || true
  log "[✓] Sysctl tuning & BBR config removed."
}

uninstall_waf_cron() {
  safe_rm /usr/local/bin/waf-update.sh
  crontab -l 2>/dev/null | grep -v "waf-update.sh" | crontab - 2>/dev/null || true
  log "[✓] WAF auto-update cron removed."
}

uninstall_wpcli() {
  safe_rm /usr/local/bin/wp
  log "[✓] WP-CLI removed."
}

uninstall_dependencies() {
  apt_purge_if_installed software-properties-common curl dirmngr gnupg \
    ca-certificates lsb-release zip unzip tar jq
}

repo_key_cleanup_misc() {
  sed -i '/ondrej/d;/mariadb/d;/nginx\.org/d' /etc/apt/sources.list 2>/dev/null || true
  find /etc/apt/sources.list.d/ -type f -name "*.list" -exec sed -i '/ondrej/d;/mariadb/d;/nginx\.org/d' {} \; 2>/dev/null || true

  safe_rm /etc/apt/trusted.gpg.d/ondrej-php.gpg
  safe_rm /etc/apt/trusted.gpg.d/ondrej-archive.gpg
  safe_rm /usr/share/keyrings/mariadb-keyring.gpg
  safe_rm /usr/share/keyrings/nginx-archive-keyring.gpg
  safe_rm /etc/apt/sources.list.d/nginx.list
  safe_rm /etc/apt/sources.list.d/mariadb.list
  safe_rm /etc/apt/preferences.d/99-nginx
  safe_rm /etc/apt/preferences.d/nginx-pin
  safe_rm /etc/systemd/system/mariadb.service.d

  log "[✓] All repo keys, sources, and preferences cleaned."
}

# ---------------------------------------------------
# FINAL STEPS
# ---------------------------------------------------

apt_finish() {
  log "[+] Cleaning up apt..."
  apt-get update >> "$LOGFILE" 2>&1 || true
  apt-get autoremove -y >> "$LOGFILE" 2>&1 || true
  apt-get autoclean -y >> "$LOGFILE" 2>&1 || true
  log "[✓] Cleanup done."
}

summary() {
  log "------------ UNINSTALL SUMMARY ------------"
  printf "%s\n" "${STEP_STATUS[@]}" | tee -a "$LOGFILE"
  log "-------------------------------------------"
}

# ---------------------------------------------------
# MENU
# ---------------------------------------------------

menu() {
  echo "======== UNINSTALLER LEMP FULL CLEAN ========"
  echo "1) NGINX"
  echo "2) PHP"
  echo "3) MariaDB"
  echo "4) phpMyAdmin"
  echo "5) Fail2Ban"
  echo "6) iptables rules"
  echo "7) Bad Bot Blocker"
  echo "8) Certbot"
  echo "9) FileManager"
  echo "10) Redis"
  echo "11) Remove ALL sites (/home/*, vhosts, pools)"
  echo "12) Remove swapfile"
  echo "13) Sysctl & BBR tuning"
  echo "14) WAF auto-update cron"
  echo "15) WP-CLI"
  echo "16) Repo/GPG cleanup"
  echo "17) Dependencies cleanup"
  echo "A) UNINSTALL ALL (everything, full fresh server)"
  echo "0) Exit"
  read -rp "Choose: " x

  case "$x" in
    1) run_step "NGINX" uninstall_nginx ;;
    2) run_step "PHP" uninstall_php ;;
    3) run_step "MariaDB" uninstall_mariadb ;;
    4) run_step "phpMyAdmin" uninstall_phpmyadmin ;;
    5) run_step "Fail2Ban" uninstall_fail2ban ;;
    6) run_step "iptables" uninstall_iptables ;;
    7) run_step "BadBot" uninstall_badbot ;;
    8) run_step "Certbot" uninstall_certbot ;;
    9) run_step "FileManager" uninstall_filemanager ;;
    10) run_step "Redis" uninstall_redis ;;
    11) run_step "ALL Sites" uninstall_all_sites ;;
    12) run_step "Swap" uninstall_swap ;;
    13) run_step "Sysctl/BBR" uninstall_sysctl ;;
    14) run_step "WAF Cron" uninstall_waf_cron ;;
    15) run_step "WP-CLI" uninstall_wpcli ;;
    16) run_step "Repo/Key cleanup" repo_key_cleanup_misc ;;
    17) run_step "Dependencies" uninstall_dependencies ;;
    A)
      run_step "ALL Sites" uninstall_all_sites
      run_step "phpMyAdmin" uninstall_phpmyadmin
      run_step "FileManager" uninstall_filemanager
      run_step "BadBot" uninstall_badbot
      run_step "Fail2Ban" uninstall_fail2ban
      run_step "Certbot" uninstall_certbot
      run_step "WAF Cron" uninstall_waf_cron
      run_step "WP-CLI" uninstall_wpcli
      run_step "NGINX" uninstall_nginx
      run_step "PHP" uninstall_php
      run_step "MariaDB" uninstall_mariadb
      run_step "Redis" uninstall_redis
      run_step "iptables" uninstall_iptables
      run_step "Sysctl/BBR" uninstall_sysctl
      run_step "Swap" uninstall_swap
      run_step "Repo/Key cleanup" repo_key_cleanup_misc
      run_step "Dependencies" uninstall_dependencies
      ;;
    0) exit 0 ;;
    *) echo "Invalid option"; exit 1 ;;
  esac

  apt_finish
  summary
}

if [[ $EUID -ne 0 ]]; then
  echo "Run as ROOT!"
  exit 1
fi

menu
