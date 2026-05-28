#!/usr/bin/env bash
set -e

REMOTE_BASE="https://vps.fio.link"

usage() {
  echo "Usage:"
  echo "  PHP App:"
  echo "    add-site.sh -d domain.com -php 8.3 -app wordpress|general -ssl le|self|none [-http3]"
  echo
  echo "  Static Site:"
  echo "    add-site.sh -d domain.com -static -ssl le|self|none [-http3]"
  echo
  echo "  Reverse Proxy (LB / Routes):"
  echo "    add-site.sh -d domain.com [proxy options...] [-http3]"
  echo
  echo "  (All proxy options are forwarded 1:1 to add-site-proxy.sh)"
  exit 1
}

# ====================
# PARSE ARGS (DETECT ONLY)
# ====================

DOMAIN=""
PHP_VERSION=""
APP=""
SSL_TYPE=""
BACKENDS=""
ROUTES=""
IS_STATIC=false

PASS_THROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)
      DOMAIN="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    -php)
      PHP_VERSION="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    -app)
      APP="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    -static)
      IS_STATIC=true
      shift
      ;;
    -backends)
      BACKENDS="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    -routes)
      ROUTES="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    -ssl)
      SSL_TYPE="$2"
      PASS_THROUGH_ARGS+=("$1" "$2")
      shift 2
      ;;
    *)
      PASS_THROUGH_ARGS+=("$1")
      shift
      ;;
  esac
done

[[ -z "$DOMAIN" ]] && usage

# ====================
# MODE DETECTION
# ====================

# --- STATIC SITE MODE ---
if [[ "$IS_STATIC" == true ]]; then
  [[ -n "$PHP_VERSION" || -n "$BACKENDS" || -n "$ROUTES" ]] && {
    echo "[x] ERROR: Cannot mix -static with PHP or Proxy options"
    exit 1
  }

  echo "[i] Detected mode: Static Site"

  exec bash <(curl -fsSL "$REMOTE_BASE/add-site-static.sh") \
    "${PASS_THROUGH_ARGS[@]}"
fi

# --- PHP APP MODE ---
if [[ -n "$PHP_VERSION" ]]; then
  [[ -n "$BACKENDS" || -n "$ROUTES" ]] && {
    echo "[x] ERROR: Cannot mix PHP App mode with proxy options"
    exit 1
  }

  [[ -z "$APP" ]] && {
    echo "[x] ERROR: -app is required when using -php"
    exit 1
  }

  if [[ "$APP" != "wordpress" && "$APP" != "general" ]]; then
    echo "[x] ERROR: Invalid -app value: $APP"
    exit 1
  fi

  echo "[i] Detected mode: PHP App ($APP)"

  exec bash <(curl -fsSL "$REMOTE_BASE/add-site-app.sh") \
    "${PASS_THROUGH_ARGS[@]}"
fi

# --- PROXY MODE ---
if [[ -n "$BACKENDS" || -n "$ROUTES" ]]; then
  echo "[i] Detected mode: Reverse Proxy"

  exec bash <(curl -fsSL "$REMOTE_BASE/add-site-proxy.sh") \
    "${PASS_THROUGH_ARGS[@]}"
fi

# ====================
# NO MODE
# ====================
echo "[x] ERROR: Unable to detect mode."
echo "    Use:"
echo "      -static      (Static Site mode)"
echo "      -php + -app  (PHP App mode)"
echo "      -backends or -routes (Proxy mode)"
usage
