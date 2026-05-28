#!/bin/bash

set -e
WAF_DIR="/etc/nginx/bots.d"
GLOBAL_DIR="/etc/nginx/conf.d"

echo "[+] Checking for WAF updates from MitchellKrogza..."

# Temporary folder
TMPDIR=$(mktemp -d)
cd "$TMPDIR"

# Files to download
BASE_URL="https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master"
FILES=(
    "conf.d/globalblacklist.conf"
    "bots.d/blockbots.conf"
    "bots.d/ddos.conf"
    "bots.d/blacklist-user-agents.conf"
)

for file_path in "${FILES[@]}"; do
    file_name=$(basename "$file_path")
    echo "[+] Downloading $file_name..."
    wget -q "$BASE_URL/$file_path" -O "$file_name"
    
    if [[ ! -s "$file_name" ]]; then
        echo "[x] ERROR: $file_name is empty or download failed! Aborting."
        rm -rf "$TMPDIR"
        exit 1
    fi
done

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
