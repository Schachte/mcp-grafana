#!/bin/bash

set -euo pipefail

DOMAIN="${2:-${GRAFANA_DOMAIN:-grafana.example.com}}"
OUTPUT="${1:-/tmp/grafana_cookie.txt}"
GRAFANA_URL="https://${DOMAIN}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_deps() {
    local missing=()
    command -v get-cookie >/dev/null 2>&1 || missing+=("get-cookie (npm install -g @mherod/get-cookie)")
    command -v cloudflared >/dev/null 2>&1 || missing+=("cloudflared (brew install cloudflared)")
    command -v curl >/dev/null 2>&1 || missing+=("curl")

    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing dependencies:"
        for dep in "${missing[@]}"; do
            echo "  - $dep"
        done
        exit 1
    fi
}

extract_browser_cookies() {
    log_info "Extracting browser cookies for ${DOMAIN}..."

    local output
    output=$(get-cookie "%" "$DOMAIN" --output json 2>&1) || {
        log_error "Failed to run get-cookie. Make sure you're logged into ${DOMAIN} in Chrome."
        return 1
    }

    CF_APP_SESSION=$(echo "$output" | grep -A3 '"name": "CF_AppSession"' | grep '"value"' | sed 's/.*"value": "//' | sed 's/".*//' | grep -oE '[a-f0-9]{16,}$' || true)
    GRAFANA_SESSION=$(echo "$output" | grep -A3 '"name": "grafana_session"' | grep '"value"' | sed 's/.*"value": "//' | sed 's/".*//' | grep -oE '[a-f0-9]{32}$' || true)
    GRAFANA_EXPIRY=$(echo "$output" | grep -A3 '"name": "grafana_session_expiry"' | grep '"value"' | sed 's/.*"value": "//' | sed 's/".*//' | grep -oE '[0-9]{10}$' || true)

    if [ -z "$GRAFANA_SESSION" ]; then
        log_error "Could not extract grafana_session from browser."
        log_warn "Make sure you're logged into ${GRAFANA_URL} in Chrome."
        return 1
    fi

    log_info "Extracted browser cookies:"
    echo "    CF_AppSession: ${CF_APP_SESSION:-<not found>}"
    echo "    grafana_session: ${GRAFANA_SESSION}"
    echo "    grafana_session_expiry: ${GRAFANA_EXPIRY:-<not found>}"
}

get_cf_token() {
    log_info "Getting fresh Cloudflare Access token..."

    CF_AUTHORIZATION=$(cloudflared access token --app "${GRAFANA_URL}" 2>/dev/null) || {
        log_error "Failed to get Cloudflare Access token."
        log_warn "Try running: cloudflared access login ${GRAFANA_URL}"
        return 1
    }

    if [ -z "$CF_AUTHORIZATION" ]; then
        log_error "Cloudflare Access token is empty."
        return 1
    fi

    log_info "Got fresh CF_Authorization token (${#CF_AUTHORIZATION} chars)"
}

save_cookies() {
    log_info "Saving cookies to ${OUTPUT}..."

    local cookie_parts=()

    [ -n "${CF_APP_SESSION:-}" ] && cookie_parts+=("CF_AppSession=${CF_APP_SESSION}")
    [ -n "${CF_AUTHORIZATION:-}" ] && cookie_parts+=("CF_Authorization=${CF_AUTHORIZATION}")
    [ -n "${GRAFANA_SESSION:-}" ] && cookie_parts+=("grafana_session=${GRAFANA_SESSION}")
    [ -n "${GRAFANA_EXPIRY:-}" ] && cookie_parts+=("grafana_session_expiry=${GRAFANA_EXPIRY}")

    if [ ${#cookie_parts[@]} -eq 0 ]; then
        log_error "No cookies to save!"
        return 1
    fi

    local IFS="; "
    local cookie_string="${cookie_parts[*]}"

    mkdir -p "$(dirname "$OUTPUT")" 2>/dev/null || true

    echo "$cookie_string" > "$OUTPUT"
    chmod 600 "$OUTPUT"

    log_info "Cookies saved to ${OUTPUT}"
}

verify_cookies() {
    log_info "Verifying cookies with ${GRAFANA_URL}/api/user..."

    local cookie
    cookie=$(cat "$OUTPUT")

    local http_code
    local body

    body=$(curl -s -w "\n%{http_code}" \
        -H "Cookie: ${cookie}" \
        "${GRAFANA_URL}/api/user" 2>&1)

    http_code=$(echo "$body" | tail -1)
    body=$(echo "$body" | sed '$d')

    if [ "$http_code" = "200" ]; then
        log_info "Cookie verification successful! (HTTP 200)"

        local email
        email=$(echo "$body" | grep -o '"email":"[^"]*"' | cut -d'"' -f4 || true)
        if [ -n "$email" ]; then
            log_info "Authenticated as: ${email}"
        fi
        return 0
    else
        log_error "Cookie verification failed! (HTTP ${http_code})"
        echo "Response: ${body}"
        return 1
    fi
}

main() {
    echo "=========================================="
    echo " Grafana Cookie Refresh Script"
    echo "=========================================="
    echo ""

    check_deps
    extract_browser_cookies
    get_cf_token
    save_cookies

    echo ""
    verify_cookies

    echo ""
    echo "=========================================="
    log_info "Done! Cookie file: ${OUTPUT}"
    echo ""
    echo "Usage with mcp-grafana:"
    echo "  GRAFANA_URL=${GRAFANA_URL} \\"
    echo "  GRAFANA_SESSION_COOKIE_FILE=${OUTPUT} \\"
    echo "  go run ./cmd/mcp-grafana"
    echo "=========================================="
}

main "$@"
