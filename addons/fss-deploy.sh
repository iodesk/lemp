#!/bin/bash
set -e

FSS_BASE="/usr/local/fss"
FSS_DATA="/opt/fss"
FSS_CONF="$FSS_DATA/conf"
FSS_SECRETS="$FSS_DATA/data"

if [[ $EUID -ne 0 ]]; then
  echo "[x] Run as root"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[+] Deploying FSS management layer..."

mkdir -p "$FSS_BASE/lib/add" "$FSS_BASE/lib/rm"
mkdir -p "$FSS_DATA/conf" "$FSS_SECRETS" "$FSS_DATA/wp/fsscache"
mkdir -p /var/log/fss

cp "$SCRIPT_DIR/fss-site" "$FSS_BASE/fss-site"
cp "$SCRIPT_DIR/fss-install" "$FSS_BASE/fss-install"
cp "$SCRIPT_DIR/fss-uninstall" "$FSS_BASE/fss-uninstall"
cp "$SCRIPT_DIR/lib/env.sh" "$FSS_BASE/lib/env.sh"
cp "$SCRIPT_DIR/lib/validate.sh" "$FSS_BASE/lib/validate.sh"
cp "$SCRIPT_DIR/lib/add/app.sh" "$FSS_BASE/lib/add/app.sh"
cp "$SCRIPT_DIR/lib/add/static.sh" "$FSS_BASE/lib/add/static.sh"
cp "$SCRIPT_DIR/lib/add/proxy.sh" "$FSS_BASE/lib/add/proxy.sh"
cp "$SCRIPT_DIR/lib/rm/app.sh" "$FSS_BASE/lib/rm/app.sh"
cp "$SCRIPT_DIR/lib/rm/static.sh" "$FSS_BASE/lib/rm/static.sh"
cp "$SCRIPT_DIR/lib/rm/proxy.sh" "$FSS_BASE/lib/rm/proxy.sh"

chmod +x "$FSS_BASE/fss-site" "$FSS_BASE/fss-install" "$FSS_BASE/fss-uninstall"

ln -sf "$FSS_BASE/fss-site" /usr/local/bin/fss-site
ln -sf "$FSS_BASE/fss-install" /usr/local/bin/fss-install
ln -sf "$FSS_BASE/fss-uninstall" /usr/local/bin/fss-uninstall

cp -r "$SCRIPT_DIR/conf/"* "$FSS_CONF/"

if [[ -d "$SCRIPT_DIR/wp/fsscache" ]]; then
  cp "$SCRIPT_DIR/wp/fsscache/fss-cache-manager.zip" "$FSS_DATA/wp/fsscache/" 2>/dev/null || true
  cp "$SCRIPT_DIR/wp/fsscache/fss-cache-manager-manifest.json" "$FSS_DATA/wp/fsscache/" 2>/dev/null || true
  echo "[✓] fsscache deployed"
fi

if [[ -d "$SCRIPT_DIR/tools" ]]; then
  mkdir -p "$FSS_BASE/tools"
  cp "$SCRIPT_DIR/tools/"* "$FSS_BASE/tools/" 2>/dev/null || true
  chmod +x "$FSS_BASE/tools/"*.sh 2>/dev/null || true
  echo "[✓] tools deployed"
fi

if [[ -d "$SCRIPT_DIR/addons" ]]; then
  mkdir -p "$FSS_BASE/addons"
  cp "$SCRIPT_DIR/addons/"* "$FSS_BASE/addons/" 2>/dev/null || true
  chmod +x "$FSS_BASE/addons/"*.sh 2>/dev/null || true
  echo "[✓] addons deployed"
fi

echo ""
echo "[✓] FSS deployed to $FSS_BASE"
echo "[✓] Configs at $FSS_CONF"
echo "[✓] Data at $FSS_DATA"
echo ""
echo "Commands available:"
echo "  fss-site add app example.com -php 8.4 -ssl le -app wordpress"
echo "  fss-site add static example.com -ssl le"
echo "  fss-site add proxy example.com -backends '127.0.0.1:8080' -ssl le"
echo "  fss-site rm example.com"
