#!/bin/bash

set -e
WAF_DIR="/etc/nginx/bots.d"
GLOBAL_DIR="/etc/nginx/conf.d"

echo "[+] Checking for WAF updates from MitchellKrogza..."

# Temporary folder
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Download blacklist (latest)
wget -q https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/conf.d/globalblacklist.conf -O globalblacklist.conf
wget -q https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/bots.d/blockbots.conf -O blockbots.conf
wget -q https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/bots.d/ddos.conf -O ddos.conf
wget -q https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/bots.d/blacklist-user-agents.conf -O blacklist-user-agents.conf

echo "[+] Applying return 403 fix..."
sed -i 's/return 444;/return 403;/g' ./*.conf

echo "[+] Backing up existing WAF config..."
mkdir -p /etc/nginx/waf_backup
cp $WAF_DIR/*.conf /etc/nginx/waf_backup/ 2>/dev/null || true
cp $GLOBAL_DIR/globalblacklist.conf /etc/nginx/waf_backup/ 2>/dev/null || true

echo "[+] Installing updated WAF files..."
cp blockbots.conf $WAF_DIR/
cp ddos.conf $WAF_DIR/
cp blacklist-user-agents.conf $WAF_DIR/
cp globalblacklist.conf /etc/nginx/conf.d/globalblacklist.conf

echo "[+] Testing NGINX config..."
if nginx -t; then
    echo "[✓] NGINX configuration OK — reloading..."
    systemctl reload nginx
    echo "[✓] WAF updated successfully."
else
    echo "[x] ERROR detected — restoring backup!"
    cp /etc/nginx/waf_backup/*.conf $WAF_DIR/
    cp /etc/nginx/waf_backup/globalblacklist.conf $GLOBAL_DIR/
    nginx -t && systemctl reload nginx
    echo "[!] Rollback complete."
fi

rm -rf "$TMPDIR"
