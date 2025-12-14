# Grafana MCP Session Cookie Hack

Minimal fork that authenticates using your existing Grafana browser session instead of a service account token.

[Official MCP Grafana repo](https://github.com/grafana/mcp-grafana)

## Prerequisites

```bash
# Enables automatic cookie extraction from Chrome
npm install -g @mherod/get-cookie
```

## Build

```bash
go mod tidy
go build ./cmd/mcp-grafana
```

## Run

```bash
# Create config directory
mkdir -p ~/.config/grafana-mcp

# Set environment variables
export GRAFANA_URL="https://grafana.yourdomain.com"
export GRAFANA_SESSION_COOKIE_FILE="$HOME/.config/grafana-mcp/session-cookie.txt"

# Start the server
./mcp-grafana \
  -transport streamable-http \
  -disable-proxied \
  -address 127.0.0.1:3010 \
  -log-level debug

# Verify the cookie works (optional)
curl -H "Cookie: $(cat "$GRAFANA_SESSION_COOKIE_FILE")" "$GRAFANA_URL/api/user"
```

## How authentication works

This implements session cookie authentication for Grafana with automatic refresh capability.

**Core Flow:**

1. **Configuration**: Set `GRAFANA_SESSION_COOKIE_FILE` to a file path (e.g., `~/.grafana-session`). Optionally seed it with a cookie value or leave empty for auto-login.

2. **Request Interception**: `SessionCookieRoundTripper` wraps all HTTP requests and injects the `Cookie` header from the file.

3. **Auto-Refresh on 401/403**: If a request fails with unauthorized:
   - Attempts to extract fresh cookies from your browser using `get-cookie` CLI or the `kooky` library
   - Falls back to opening a browser for login, then re-reads cookies via `kooky` (no manual paste path)
   - Saves the new cookie to the file and retries the request; if no cookie is found after login, the request fails with an error

4. **Cookie Sources** (tried in order):
   - `get-cookie` CLI tool (if installed)
   - Explicit cookie DB via `GRAFANA_BROWSER_COOKIES_FILE` (e.g., Chrome `Cookies` SQLite path)
   - `kooky` library reading Chrome cookies directly
   - Browser login, then `kooky` re-read (errors if no cookie is found)

**Key Detail**: When using session cookies, API key authentication is disabled (`apiKey = ""`), so requests rely entirely on the cookie. The cookie file acts as a persistent cache that survives restarts and auto-updates when expired.
## Configuration

| Variable | Description |
|----------|-------------|
| `GRAFANA_URL` | Your Grafana instance URL |
| `GRAFANA_SESSION_COOKIE_FILE` | Path to store the session cookie (preferred) |
| `GRAFANA_SESSION_COOKIE` | Alternative: pass the cookie value directly via env |
| `GRAFANA_BROWSER_COOKIES_FILE` | Optional: path to a browser cookie DB (e.g., Chrome `Cookies` SQLite) |

## Tips

- Secure the cookie file: `chmod 600 ~/.config/grafana-mcp/session-cookie.txt`
- To force re-authentication, delete the cookie file
- No API key or service account needed — just a valid browser session
