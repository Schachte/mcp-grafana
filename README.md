# Grafana MCP Session Cookie Hack

Minimal fork that authenticates using your existing Grafana browser session instead of a service account token.

[Official MCP Grafana repo](https://github.com/grafana/mcp-grafana)

## Prerequisites

```bash
npm install -g @mherod/get-cookie   # Cookie extraction from Chrome
brew install cloudflared             # For Cloudflare Access tokens (if applicable)
```

## Build

```bash
go build ./cmd/mcp-grafana
```

## Quick Start

```bash
# 1. Refresh cookies (extracts from browser + gets fresh CF token)
GRAFANA_DOMAIN=grafana.example.com ./refresh_grafana_cookie.sh /tmp/grafana_cookie.txt

# 2. Run the server
GRAFANA_URL=https://grafana.example.com \
GRAFANA_SESSION_COOKIE_FILE=/tmp/grafana_cookie.txt \
./mcp-grafana \
  -transport streamable-http \
  -address 127.0.0.1:5250 \
  -endpoint-path /mcp \
  -log-level debug
```

## Verify with MCP Inspector

```bash
# Install MCP inspector
npx @anthropic-ai/mcp-inspector

# Connect to the running server
# URL: http://127.0.0.1:5250/mcp
# Transport: Streamable HTTP
```

Or test manually:

```bash
# Initialize
curl -X POST http://127.0.0.1:5250/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}},"id":1}'

# List tools
curl -X POST http://127.0.0.1:5250/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","params":{},"id":2}'
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
