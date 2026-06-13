#!/usr/bin/env bash
set -e

PHP_VERSION="${1:-8.4}"
IONCUBE_DOWNLOAD="https://downloads.ioncube.com/loader_downloads/ioncube_loaders_lin_x86-64.tar.gz"
WORK_DIR="/tmp/ioncube_install_$$"

echo "[+] Installing ionCube Loader for PHP $PHP_VERSION..."

if ! command -v php$PHP_VERSION >/dev/null 2>&1; then
  echo "[x] PHP $PHP_VERSION not installed."
  exit 1
fi

mkdir -p "$WORK_DIR"
curl -sSL --connect-timeout 10 --max-time 120 "$IONCUBE_DOWNLOAD" -o "$WORK_DIR/ioncube.tar.gz"
tar -xzf "$WORK_DIR/ioncube.tar.gz" -C "$WORK_DIR"

PHP_API_DIR=$(php$PHP_VERSION -i | grep "^extension_dir" | awk '{print $3}')
LOADER_FILE="ioncube_loader_lin_${PHP_VERSION}.so"

if [[ ! -f "$WORK_DIR/ioncube/$LOADER_FILE" ]]; then
  echo "[x] ionCube loader for PHP $PHP_VERSION not found in archive."
  rm -rf "$WORK_DIR"
  exit 1
fi

cp "$WORK_DIR/ioncube/$LOADER_FILE" "$PHP_API_DIR/"

echo "zend_extension=$PHP_API_DIR/$LOADER_FILE" > "/etc/php/$PHP_VERSION/fpm/conf.d/00-ioncube.ini"
echo "zend_extension=$PHP_API_DIR/$LOADER_FILE" > "/etc/php/$PHP_VERSION/cli/conf.d/00-ioncube.ini"

systemctl restart php$PHP_VERSION-fpm

echo "[✓] ionCube installed for PHP $PHP_VERSION"
php$PHP_VERSION -m | grep -i ioncube && echo "[✓] Verified: ionCube loaded" || echo "[!] Warning: ionCube not showing in modules"

rm -rf "$WORK_DIR"
