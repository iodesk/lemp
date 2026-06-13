#!/usr/bin/env bash

validate_domain() {
  local domain="$1"
  if [[ -z "$domain" ]]; then
    echo "[x] ERROR: Domain is required"
    exit 1
  fi
  if ! is_valid_domain "$domain"; then
    echo "[x] ERROR: Invalid domain: $domain"
    exit 1
  fi
}

validate_php_version() {
  local version="$1"
  if [[ -z "$version" ]]; then
    echo "[x] ERROR: PHP version is required"
    exit 1
  fi
  if ! is_supported_php "$version"; then
    echo "[x] ERROR: Unsupported PHP version: $version"
    exit 1
  fi
}

validate_app_type() {
  local app="$1"
  if [[ -z "$app" ]]; then
    echo "[x] ERROR: App type is required (-app wordpress|general)"
    exit 1
  fi
  if ! is_supported_app "$app"; then
    echo "[x] ERROR: Unsupported app type: $app"
    exit 1
  fi
}

check_user_exists() {
  local user="$1"
  id "$user" &>/dev/null
}

check_nginx_conf_exists() {
  local domain="$1"
  [[ -f "/etc/nginx/sites-available/$domain.conf" ]]
}

check_mysql_root_password() {
  if [[ ! -f "$MYSQL_PASS_FILE" ]]; then
    log "[x] ERROR: MariaDB root password not found at $MYSQL_PASS_FILE"
    exit 1
  fi
}
