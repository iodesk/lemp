#!/usr/bin/env bash

FSS_BASE="/usr/local/fss"
FSS_DATA="/opt/fss"
FSS_CONF="$FSS_DATA/conf"
FSS_SECRETS="$FSS_DATA/data"
LOG_DIR="/var/log/fss"
USER_NGINX="nginx"
FB_HOST="http://127.0.0.1:2222"
FB_TOKEN_FILE="$FSS_SECRETS/.filebrowser_token"
FB_ADMIN_FILE="$FSS_SECRETS/.filebrowser_admin"
MYSQL_PASS_FILE="$FSS_SECRETS/.mysql_root_password"
CURL_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"

mkdir -p "$LOG_DIR"

mycurl() { curl -fsSL -A "$CURL_UA" "$@"; }

log() {
  echo "[$(date +'%F %T')] $*" | tee -a "$LOG_FILE"
}

generate_password() {
  tr -dc 'A-Za-z0-9' </dev/urandom | head -c 20
}

is_valid_domain() {
  [[ "$1" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

is_supported_php() {
  [[ "$1" == "8.4" || "$1" == "8.3" || "$1" == "8.2" || "$1" == "8.1" ]]
}

is_supported_app() {
  [[ "$1" == "wordpress" || "$1" == "general" ]]
}

get_user_from_domain() {
  local domain="$1"
  local maxlen=32

  domain=$(echo "$domain" | sed 's|^https\?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]')

  IFS='.' read -ra p <<< "$domain"
  local n=${#p[@]}
  (( n < 2 )) && return 1

  local tld_parts=1
  if (( n >= 3 )); then
    local p2="${p[$((n-2))]}"
    if [[ " co my web ac go or biz net com sch org " =~ " $p2 " ]]; then
      tld_parts=2
    fi
  fi

  local base_idx=$(( n - tld_parts - 1 ))
  if (( base_idx < 0 )); then
    echo "${p[0]:0:maxlen}"
    return 0
  fi

  local name="${p[$base_idx]}"
  for (( i=base_idx-1; i>=0; i-- )); do
    name="${name}-${p[$i]}"
  done

  name="$(echo "$name" | sed 's/[^a-z0-9-]/-/g; s/-\+/-/g; s/^-//; s/-$//')"
  echo "${name:0:maxlen}"
}

get_default_username() {
  local domain="$1"
  domain=$(echo "$domain" | sed 's|^https\?://||; s|/.*$||' | tr '[:upper:]' '[:lower:]')
  local name="${domain//./}"
  name="$(echo "$name" | sed 's/[^a-z0-9]//g')"
  echo "${name:0:32}"
}

calc_max_children() {
  local ram_mb
  ram_mb=$(grep MemTotal /proc/meminfo | awk '{print int($2/1024)}')
  local per_worker=50
  local usable_ram=$(( ram_mb * 60 / 100 ))
  local max_children=$(( usable_ram / per_worker ))
  if (( max_children < 8 )); then
    max_children=8
  fi
  echo "$max_children"
}

detect_other_domains() {
  local user="$1"
  local current_domain="$2"
  local user_home="/home/$user"
  local others=()

  for dir in "$user_home"/*/public_html; do
    [[ -d "$dir" ]] || continue
    local d
    d=$(basename "$(dirname "$dir")")
    [[ "$d" == "$current_domain" ]] && continue
    [[ "$d" =~ \. ]] && others+=("$d")
  done

  if [[ ${#others[@]} -gt 0 ]]; then
    printf '%s\n' "${others[@]}"
    return 0
  fi
  return 1
}

setup_ssl() {
  local ssl_type="$1"
  local domain="$2"
  local nginx_conf="$3"
  local http3="${4:-off}"

  if [[ "$ssl_type" == "le" ]]; then
    local dummy_dir="/etc/ssl/selfsigned"
    local dummy_cert="$dummy_dir/$domain.crt"
    local dummy_key="$dummy_dir/$domain.key"
    mkdir -p "$dummy_dir"

    if [[ ! -f "$dummy_cert" || ! -f "$dummy_key" ]]; then
      openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
        -keyout "$dummy_key" \
        -out "$dummy_cert" \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$domain"
      log "[✓] Dummy SSL generated for $domain"
    fi

    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 ssl;|listen [::]:443 ssl;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$nginx_conf"

    if [[ "$http3" == "on" ]]; then
      sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 quic;|listen 443 quic;|g" "$nginx_conf"
      sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 quic;|listen [::]:443 quic;|g" "$nginx_conf"
      sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http3 on;|http3 on;|g" "$nginx_conf"
      sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*add_header Alt-Svc.*|add_header Alt-Svc 'h3=\":443\"; ma=86400' always;|g" "$nginx_conf"
    else
      sed -i "/#LE-SSL.*listen 443 quic/d" "$nginx_conf"
      sed -i "/#LE-SSL.*\[::\]:443 quic/d" "$nginx_conf"
      sed -i "/#LE-SSL.*http3/d" "$nginx_conf"
      sed -i "/#LE-SSL.*Alt-Svc/d" "$nginx_conf"
    fi

    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $dummy_cert;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $dummy_key;|g" "$nginx_conf"

    if ! grep -q "ssl_certificate " "$nginx_conf"; then
      log "[!] ssl_certificate not found after sed — SSL setup incomplete"
      return 0
    fi

    if nginx -t; then
      systemctl reload nginx
      log "[✓] NGINX reloaded with dummy cert"
    else
      log "[!] NGINX config invalid after dummy cert config — continuing without SSL"
      return 0
    fi

    local request_www=false
    if command -v dig >/dev/null 2>&1 && dig +short "www.$domain" 2>/dev/null | grep -qE '.'; then
      request_www=true
      log ">> DNS www.$domain detected"
    fi

    if [[ "$request_www" == true ]]; then
      if certbot certonly --nginx --non-interactive --agree-tos --email "admin@$domain" \
        -d "$domain" -d "www.$domain"; then
        log "[✓] Certbot succeeded with www and non-www"
      else
        if certbot certonly --nginx --non-interactive --agree-tos --email "admin@$domain" -d "$domain"; then
          log "[✓] Certbot succeeded without www"
        else
          log "[!] Certbot failed. Using self-signed cert instead. You can retry SSL later."
          setup_certbot_cron
          return 0
        fi
      fi
    else
      if certbot certonly --nginx --non-interactive --agree-tos --email "admin@$domain" -d "$domain"; then
        log "[✓] Certbot succeeded (non-www only)"
      else
        log "[!] Certbot failed. Using self-signed cert instead. You can retry SSL later."
        setup_certbot_cron
        return 0
      fi
    fi

    local real_cert="/etc/letsencrypt/live/$domain/fullchain.pem"
    local real_key="/etc/letsencrypt/live/$domain/privkey.pem"

    if [[ -f "$real_cert" && -f "$real_key" ]]; then
      sed -i "s|ssl_certificate .*|ssl_certificate $real_cert;|g" "$nginx_conf"
      sed -i "s|ssl_certificate_key .*|ssl_certificate_key $real_key;|g" "$nginx_conf"

      if nginx -t; then
        systemctl reload nginx
        log "[✓] NGINX reloaded with Let's Encrypt certificate"
      else
        log "[!] NGINX config invalid after switching to real cert. Keeping self-signed."
      fi
    else
      log "[!] Certbot succeeded but cert files not found. Keeping self-signed."
    fi

    setup_certbot_cron

  elif [[ "$ssl_type" == "self" ]]; then
    local dummy_dir="/etc/ssl/selfsigned"
    local dummy_cert="$dummy_dir/$domain.crt"
    local dummy_key="$dummy_dir/$domain.key"
    mkdir -p "$dummy_dir"

    if [[ ! -f "$dummy_cert" || ! -f "$dummy_key" ]]; then
      openssl req -x509 -nodes -days 360 -newkey rsa:2048 \
        -keyout "$dummy_key" \
        -out "$dummy_cert" \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SelfSigned/CN=$domain"
      log "[✓] Self-signed SSL generated for $domain"
    fi

    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen 443 ssl;|listen 443 ssl;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*listen \[::\]:443 ssl;|listen [::]:443 ssl;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*http2 on;|http2 on;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate .*|ssl_certificate $dummy_cert;|g" "$nginx_conf"
    sed -i "s|^[[:space:]]*#LE-SSL[[:space:]]*ssl_certificate_key .*|ssl_certificate_key $dummy_key;|g" "$nginx_conf"

    sed -i "/#LE-SSL.*listen 443 quic/d" "$nginx_conf"
    sed -i "/#LE-SSL.*\[::\]:443 quic/d" "$nginx_conf"
    sed -i "/#LE-SSL.*http3/d" "$nginx_conf"
    sed -i "/#LE-SSL.*Alt-Svc/d" "$nginx_conf"

    if nginx -t; then
      systemctl reload nginx
      log "[✓] NGINX reloaded with self-signed SSL"
    else
      log "[x] ERROR: NGINX config invalid after self-signed config"
      exit 1
    fi

  elif [[ "$ssl_type" == "none" ]]; then
    sed -i '/#LE-SSL/d' "$nginx_conf"
    nginx -t && systemctl reload nginx
  fi
}

remove_ssl() {
  local domain="$1"

  rm -rf "/etc/letsencrypt/live/$domain"
  rm -rf "/etc/letsencrypt/archive/$domain"
  rm -f "/etc/letsencrypt/renewal/$domain.conf"
  rm -f "/etc/ssl/selfsigned/$domain.crt"
  rm -f "/etc/ssl/selfsigned/$domain.key"
}

setup_fb_user() {
  local user="$1"
  local fb_pass="$2"

  if [[ ! -f "$FB_TOKEN_FILE" ]]; then
    log "[FB] ERROR: Token file not found → $FB_TOKEN_FILE"
    return 1
  fi

  local token
  token=$(cat "$FB_TOKEN_FILE")

  local fb_existing
  fb_existing=$(curl -s -X GET "$FB_HOST/api/users" \
    -H "X-Auth: $token" \
    -H "Content-Type: application/json" | jq -r ".[] | select(.username==\"$user\") | .username" 2>/dev/null)

  if [[ "$fb_existing" == "$user" ]]; then
    log "[FB] User '$user' already exists in Filebrowser. Skipping."
    return 2
  fi

  log "[FB] Creating Filebrowser user: $user"

  local fb_admin_pass=""
  if [[ -f "$FB_ADMIN_FILE" ]]; then
    fb_admin_pass=$(jq -r '.password' "$FB_ADMIN_FILE")
  fi

  local fb_tmp="/tmp/fb-payload-$user.json"
  jq -n \
    --arg user "$user" \
    --arg pass "$fb_pass" \
    --arg adminpass "$fb_admin_pass" \
    '{
      "what": "user",
      "which": [],
      "data": {
        "username": $user,
        "password": $pass,
        "scope": ("/"+$user),
        "locale": "en",
        "lockPassword": false,
        "viewMode": "list",
        "singleClick": false,
        "redirectAfterCopyMove": false,
        "hideDotfiles": false,
        "dateFormat": false,
        "aceEditorTheme": "",
        "commands": [],
        "rules": [],
        "sorting": {"by":"name","asc":false},
        "perm": {
          "admin": false,
          "execute": true,
          "create": true,
          "rename": true,
          "modify": true,
          "delete": true,
          "share": true,
          "download": true
        }
      },
      "current_password": $adminpass
    }' > "$fb_tmp"

  local http_code
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$FB_HOST/api/users" \
    -H "X-Auth: $token" \
    -H "Content-Type: application/json" \
    -d @"$fb_tmp")

  if [[ "$http_code" == "201" || "$http_code" == "200" ]]; then
    log "[FB] User added successfully"
  else
    log "[FB] ERROR creating user (HTTP $http_code)"
  fi

  rm -f "$fb_tmp"
}

remove_fb_user() {
  local user="$1"

  if [[ ! -f "$FB_TOKEN_FILE" ]]; then
    log "[FB] Token file not found, skipping"
    return 1
  fi

  local token
  token=$(<"$FB_TOKEN_FILE")

  local user_list
  user_list=$(curl -s -X GET "$FB_HOST/api/users" \
    -H "Content-Type: application/json" \
    -H "X-Auth: $token")

  if [[ -z "$user_list" ]]; then
    log "[FB] ERROR: Could not fetch user list"
    return 1
  fi

  local fb_uid
  fb_uid=$(echo "$user_list" | jq ".[] | select(.username==\"$user\") | .id")

  if [[ -z "$fb_uid" || "$fb_uid" == "null" ]]; then
    log "[FB] User '$user' not found in Filebrowser"
    return 0
  fi

  log "[FB] Removing Filebrowser user '$user' (UID=$fb_uid)..."

  local fb_admin_pass=""
  if [[ -f "$FB_ADMIN_FILE" ]]; then
    fb_admin_pass=$(jq -r '.password' "$FB_ADMIN_FILE")
  fi

  local fb_del_tmp="/tmp/fb-del-$user.json"
  jq -nc --argjson uid "$fb_uid" --arg adminpass "$fb_admin_pass" \
    '{what:"user",which:[$uid],current_password:$adminpass}' > "$fb_del_tmp"

  local http_code
  http_code=$(curl -s -w "%{http_code}" -o /dev/null \
    -X DELETE "$FB_HOST/api/users/$fb_uid" \
    -H "X-Auth: $token" \
    -H "Content-Type: application/json" \
    -d @"$fb_del_tmp")
  http_code=$(echo "$http_code" | tail -n1 | tr -dc '0-9')

  if [[ "$http_code" == "200" || "$http_code" == "201" || "$http_code" == "204" ]]; then
    log "[FB] Filebrowser user '$user' deleted"
  else
    log "[FB] ERROR deleting user (HTTP $http_code)"
  fi

  rm -f "$fb_del_tmp"
}

setup_logrotate() {
  local user="$1"

  cat >/etc/logrotate.d/$user.conf <<EOF
/home/$user/logs/*/*.log
/home/$user/logs/*/*/*.log {
    su root root
    daily
    missingok
    rotate 30
    dateext
    dateformat -%Y-%m-%d
    create 0640 $USER_NGINX $user
    postrotate
      /etc/init.d/nginx reload &> /dev/null || true
    endscript
}
EOF

  log "[✓] Logrotate rules created/updated for: $user"
}

setup_certbot_cron() {
  local cron_renew="/etc/cron.d/certbot_renew"
  if [[ ! -f "$cron_renew" ]]; then
    echo "0 3 * * * root certbot renew --quiet --post-hook \"systemctl reload nginx\"" > "$cron_renew"
    log "[✓] Certbot auto-renewal cron added"
  fi
}
