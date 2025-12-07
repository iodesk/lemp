#!/bin/bash
set -euo pipefail

LOGFILE="/var/log/uninstaller.log"
PHP_VERSION="${PHP_VERSION:-8.3}"
SWAPFILE="${SWAPFILE:-/swapfile}"

mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE"

log() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOGFILE"; }

confirm() {
  read -rp "$1 [y/n] (default: $2): " yn
  yn="${yn:-$2}"
  [[ "$yn" =~ ^[Yy]$ ]]
}

safe_rm() { [[ -n "${1:-}" && "$1" != "/" ]] && rm -rf --one-file-system "$1" 2>/dev/null || true; }

has_cmd() { command -v "$1" >/dev/null 2>&1; }

svc_stop_disable() {
  systemctl stop "$1" 2>/dev/null || true
  systemctl disable "$1" 2>/dev/null || true
}

apt_purge_if_installed() {
  local pkgs=("$@")
  local installed=()
  for p in "${pkgs[@]}"; do
    dpkg -l "$p" 2>/dev/null | awk '/^ii/{print $2}' | grep -qx "$p" && installed+=("$p")
  done
  [[ ${#installed[@]} -gt 0 ]] && DEBIAN_FRONTEND=noninteractive apt-get purge -y "${installed[@]}" || true
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
  apt_purge_if_installed nginx nginx-full nginx-core libnginx-mod-http-brotli-static libnginx-mod-http-brotli-filter

  safe_rm /etc/nginx

  add-apt-repository -r -y ppa:ondrej/nginx 2>/dev/null || true
  safe_rm /etc/apt/trusted.gpg.d/ondrej-archive.gpg
  sed -i '/ondrej\/nginx/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
}

uninstall_php() {
  svc_stop_disable php${PHP_VERSION}-fpm

  apt_purge_if_installed \
    php${PHP_VERSION}-fpm php${PHP_VERSION}-cli php${PHP_VERSION}-common \
    php${PHP_VERSION}-mysql php${PHP_VERSION}-curl php${PHP_VERSION}-mbstring \
    php${PHP_VERSION}-xml php${PHP_VERSION}-gd php${PHP_VERSION}-zip php${PHP_VERSION}-bcmath php${PHP_VERSION}-redis php-common

  safe_rm /etc/php/${PHP_VERSION}

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
  safe_rm /etc/nginx/includes/phpmyadmin.conf
  remove_line /etc/nginx/includes/global.conf 'phpmyadmin'
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
}

uninstall_filemanager() {
log "---"
}

# ---------------------------------------------------
# REMOVE ALL HOSTING SITES (USER HOME, VHOST, POOLS)
# ---------------------------------------------------

uninstall_all_sites() {
  for d in /home/*; do safe_rm "$d"; done

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

uninstall_dependencies() {
  apt_purge_if_installed software-properties-common curl dirmngr gnupg \
    ca-certificates lsb-release zip unzip tar jq
}

repo_key_cleanup_misc() {
  sed -i '/ondrej/d;/mariadb/d' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
  safe_rm /etc/apt/trusted.gpg.d/ondrej-php.gpg
  safe_rm /etc/apt/trusted.gpg.d/ondrej-archive.gpg
  safe_rm /usr/share/keyrings/mariadb-keyring.gpg
}

# ---------------------------------------------------
# FINAL STEPS
# ---------------------------------------------------

apt_finish() {
  apt-get update || true
  apt-get autoremove -y || true
  apt-get autoclean -y || true
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
  echo "10) Remove ALL sites (/home/*, vhosts, pools)"
  echo "11) Remove swapfile"
  echo "12) Repo/GPG cleanup"
  echo "13) Dependencies cleanup"
  echo "A) UNINSTALL ALL (everything — full fresh server)"
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
    10) run_step "ALL Sites" uninstall_all_sites ;;
    11) run_step "Swap" uninstall_swap ;;
    12) run_step "Repo/Key cleanup" repo_key_cleanup_misc ;;
    13) run_step "Dependencies" uninstall_dependencies ;;
    A)
      run_step "NGINX" uninstall_nginx
      run_step "PHP" uninstall_php
      run_step "MariaDB" uninstall_mariadb
      run_step "phpMyAdmin" uninstall_phpmyadmin
      run_step "Fail2Ban" uninstall_fail2ban
      run_step "iptables" uninstall_iptables
      run_step "BadBot" uninstall_badbot
      run_step "Certbot" uninstall_certbot
      run_step "FileManager" uninstall_filemanager
      run_step "ALL Sites" uninstall_all_sites
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
