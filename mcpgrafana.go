package mcpgrafana

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/browserutils/kooky"
	"github.com/browserutils/kooky/browser/chrome"
	openapiRuntime "github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	"github.com/grafana/grafana-openapi-client-go/client"
	"github.com/grafana/incident-go"
	"github.com/mark3labs/mcp-go/server"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

const (
	defaultGrafanaHost = "localhost:3000"
	defaultGrafanaURL  = "http://" + defaultGrafanaHost

	grafanaURLEnvVar                 = "GRAFANA_URL"
	grafanaServiceAccountTokenEnvVar = "GRAFANA_SERVICE_ACCOUNT_TOKEN"
	grafanaAPIEnvVar                 = "GRAFANA_API_KEY" // Deprecated: use GRAFANA_SERVICE_ACCOUNT_TOKEN instead
	grafanaOrgIDEnvVar               = "GRAFANA_ORG_ID"

	grafanaUsernameEnvVar = "GRAFANA_USERNAME"
	grafanaPasswordEnvVar = "GRAFANA_PASSWORD"

	grafanaSessionCookieEnvVar  = "GRAFANA_SESSION_COOKIE"
	grafanaSessionCookieFileEnv = "GRAFANA_SESSION_COOKIE_FILE"
	grafanaBrowserCookiesFile   = "GRAFANA_BROWSER_COOKIES_FILE"

	grafanaURLHeader    = "X-Grafana-URL"
	grafanaAPIKeyHeader = "X-Grafana-API-Key"
)

func urlAndAPIKeyFromEnv() (string, string) {
	u := strings.TrimRight(os.Getenv(grafanaURLEnvVar), "/")

	// Check for the new service account token environment variable first
	apiKey := os.Getenv(grafanaServiceAccountTokenEnvVar)
	if apiKey != "" {
		return u, apiKey
	}

	// Fall back to the deprecated API key environment variable
	apiKey = os.Getenv(grafanaAPIEnvVar)
	if apiKey != "" {
		slog.Warn("GRAFANA_API_KEY is deprecated, please use GRAFANA_SERVICE_ACCOUNT_TOKEN instead. See https://grafana.com/docs/grafana/latest/administration/service-accounts/#add-a-token-to-a-service-account-in-grafana for details on creating service account tokens.")
	}

	return u, apiKey
}

func userAndPassFromEnv() *url.Userinfo {
	username := os.Getenv(grafanaUsernameEnvVar)
	password, exists := os.LookupEnv(grafanaPasswordEnvVar)
	if username == "" && password == "" {
		return nil
	}
	if !exists {
		return url.User(username)
	}
	return url.UserPassword(username, password)
}

func orgIdFromEnv() int64 {
	orgIDStr := os.Getenv(grafanaOrgIDEnvVar)
	if orgIDStr == "" {
		return 0
	}
	orgID, err := strconv.ParseInt(orgIDStr, 10, 64)
	if err != nil {
		slog.Warn("Invalid GRAFANA_ORG_ID value, ignoring", "value", orgIDStr, "error", err)
		return 0
	}
	return orgID
}

func sessionCookieFromEnv() string {
	cookieFile := os.Getenv(grafanaSessionCookieFileEnv)
	if cookieFile != "" {
		data, err := os.ReadFile(cookieFile)
		if err != nil {
			slog.Warn("Failed to read session cookie from file, falling back to env var", "file", cookieFile, "error", err)
		} else {
			cookie := strings.TrimSpace(string(data))
			if cookie != "" {
				slog.Debug("Read session cookie from file", "file", cookieFile)
				return cookie
			}
		}
	}

	cookie := os.Getenv(grafanaSessionCookieEnvVar)
	if cookie != "" {
		slog.Debug("Read session cookie from env")
	}
	return cookie
}

func hasSessionCookie(cookie, cookieFile string) bool {
	return cookie != "" || cookieFile != ""
}

func resolveSessionCookie(cookie, cookieFile string) string {
	if cookieFile == "" {
		return cookie
	}

	data, err := os.ReadFile(cookieFile)
	if err != nil {
		slog.Debug("Failed to read session cookie from file, using fallback cookie", "file", cookieFile, "error", err)
		return cookie
	}

	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return cookie
	}

	return trimmed
}

func SessionCookieConfigured(cfg GrafanaConfig) bool {
	return hasSessionCookie(cfg.SessionCookie, cfg.SessionCookieFile)
}

func SessionCookieValue(cfg GrafanaConfig) string {
	return resolveSessionCookie(cfg.SessionCookie, cfg.SessionCookieFile)
}

func formatCookieHeader(cookie string) string {
	if strings.Contains(cookie, "=") {
		return cookie
	}
	return "grafana_session=" + cookie
}

func orgIdFromHeaders(req *http.Request) int64 {
	orgIDStr := req.Header.Get(client.OrgIDHeader)
	if orgIDStr == "" {
		return 0
	}
	orgID, err := strconv.ParseInt(orgIDStr, 10, 64)
	if err != nil {
		slog.Warn("Invalid X-Grafana-Org-Id header value, ignoring", "value", orgIDStr, "error", err)
		return 0
	}
	return orgID
}

func urlAndAPIKeyFromHeaders(req *http.Request) (string, string) {
	u := strings.TrimRight(req.Header.Get(grafanaURLHeader), "/")
	apiKey := req.Header.Get(grafanaAPIKeyHeader)
	return u, apiKey
}

// grafanaConfigKey is the context key for Grafana configuration.
type grafanaConfigKey struct{}

// TLSConfig holds TLS configuration for Grafana clients.
// It supports mutual TLS authentication with client certificates, custom CA certificates for server verification, and development options like skipping certificate verification.
type TLSConfig struct {
	CertFile   string
	KeyFile    string
	CAFile     string
	SkipVerify bool
}

// GrafanaConfig represents the full configuration for Grafana clients.
// It includes connection details, authentication credentials, debug settings, and TLS options used throughout the MCP server's lifecycle.
type GrafanaConfig struct {
	// Debug enables debug mode for the Grafana client.
	Debug bool

	// IncludeArgumentsInSpans enables logging of tool arguments in OpenTelemetry spans.
	// This should only be enabled in non-production environments or when you're certain
	// the arguments don't contain PII. Defaults to false for safety.
	// Note: OpenTelemetry spans are always created for context propagation, but arguments
	// are only included when this flag is enabled.
	IncludeArgumentsInSpans bool

	// URL is the URL of the Grafana instance.
	URL string

	// APIKey is the API key or service account token for the Grafana instance.
	// It may be empty if we are using on-behalf-of auth.
	APIKey string

	// Credentials if user is using basic auth
	BasicAuth *url.Userinfo

	// OrgID is the organization ID to use for multi-org support.
	// When set, it will be sent as X-Grafana-Org-Id header regardless of authentication method.
	// Works with service account tokens, API keys, and basic authentication.
	OrgID int64

	// AccessToken is the Grafana Cloud access policy token used for on-behalf-of auth in Grafana Cloud.
	AccessToken string
	// IDToken is an ID token identifying the user for the current request.
	// It comes from the `X-Grafana-Id` header sent from Grafana to plugin backends.
	// It is used for on-behalf-of auth in Grafana Cloud.
	IDToken string

	SessionCookie string

	SessionCookieFile string

	// TLSConfig holds TLS configuration for all Grafana clients.
	TLSConfig *TLSConfig

	// Timeout specifies a time limit for requests made by the Grafana client.
	// A Timeout of zero means no timeout.
	// Default is 10 seconds.
	Timeout time.Duration
}

const (
	// DefaultGrafanaClientTimeout is the default timeout for Grafana HTTP client requests.
	DefaultGrafanaClientTimeout = 10 * time.Second
)

// WithGrafanaConfig adds Grafana configuration to the context.
// This configuration includes API credentials, debug settings, and TLS options that will be used by all Grafana clients created from this context.
func WithGrafanaConfig(ctx context.Context, config GrafanaConfig) context.Context {
	return context.WithValue(ctx, grafanaConfigKey{}, config)
}

// GrafanaConfigFromContext extracts Grafana configuration from the context.
// If no config is found, returns a zero-value GrafanaConfig. This function is typically used by internal components to access configuration set earlier in the request lifecycle.
func GrafanaConfigFromContext(ctx context.Context) GrafanaConfig {
	if config, ok := ctx.Value(grafanaConfigKey{}).(GrafanaConfig); ok {
		return config
	}
	return GrafanaConfig{}
}

// CreateTLSConfig creates a *tls.Config from TLSConfig.
// It supports client certificates, custom CA certificates, and the option to skip TLS verification for development environments.
func (tc *TLSConfig) CreateTLSConfig() (*tls.Config, error) {
	if tc == nil {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: tc.SkipVerify,
	}

	// Load client certificate if both cert and key files are provided
	if tc.CertFile != "" && tc.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tc.CertFile, tc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load CA certificate if provided
	if tc.CAFile != "" {
		caCert, err := os.ReadFile(tc.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// HTTPTransport creates an HTTP transport with custom TLS configuration.
// It clones the provided transport and applies the TLS settings, preserving other transport configurations like timeouts and connection pools.
func (tc *TLSConfig) HTTPTransport(defaultTransport *http.Transport) (http.RoundTripper, error) {
	transport := defaultTransport.Clone()

	if tc != nil {
		tlsCfg, err := tc.CreateTLSConfig()
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = tlsCfg
	}

	return transport, nil
}

// UserAgentTransport wraps an http.RoundTripper to add a custom User-Agent header.
// This ensures all HTTP requests from the MCP server are properly identified with version information for debugging and analytics.
type UserAgentTransport struct {
	rt        http.RoundTripper
	UserAgent string
}

func (t *UserAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	clonedReq := req.Clone(req.Context())

	// Add or update the User-Agent header
	if clonedReq.Header.Get("User-Agent") == "" {
		clonedReq.Header.Set("User-Agent", t.UserAgent)
	}

	return t.rt.RoundTrip(clonedReq)
}

// Version returns the version of the mcp-grafana binary.
// It uses runtime/debug to fetch version information from the build, returning "(devel)" for local development builds.
// The version is computed once and cached for performance.
var Version = sync.OnceValue(func() string {
	// Default version string returned by `runtime/debug` if built
	// from the source repository rather than with `go install`.
	v := "(devel)"
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		v = bi.Main.Version
	}
	return v
})

// UserAgent returns the user agent string for HTTP requests.
// It includes the mcp-grafana identifier and version number for proper request attribution and debugging.
func UserAgent() string {
	return fmt.Sprintf("mcp-grafana/%s", Version())
}

// NewUserAgentTransport creates a new UserAgentTransport with the specified user agent.
// If no user agent is provided, it uses the default UserAgent() with version information.
// The transport wraps the provided RoundTripper, defaulting to http.DefaultTransport if nil.
func NewUserAgentTransport(rt http.RoundTripper, userAgent ...string) *UserAgentTransport {
	if rt == nil {
		rt = http.DefaultTransport
	}

	ua := UserAgent() // default
	if len(userAgent) > 0 {
		ua = userAgent[0]
	}

	return &UserAgentTransport{
		rt:        rt,
		UserAgent: ua,
	}
}

// wrapWithUserAgent wraps an http.RoundTripper with user agent tracking
func wrapWithUserAgent(rt http.RoundTripper) http.RoundTripper {
	return NewUserAgentTransport(rt)
}

func wrapWithSessionCookie(rt http.RoundTripper, cookie, cookieFile, grafanaURL string) http.RoundTripper {
	if !hasSessionCookie(cookie, cookieFile) {
		return rt
	}
	return NewSessionCookieRoundTripper(rt, cookie, cookieFile, grafanaURL)
}

func ensureJSONConsumers(rt *httptransport.Runtime) {
	if rt == nil {
		return
	}

	jsonConsumer := openapiRuntime.JSONConsumer()
	if rt.Consumers == nil {
		rt.Consumers = map[string]openapiRuntime.Consumer{}
	}
	rt.Consumers["application/json"] = jsonConsumer
	rt.Consumers["text/plain"] = jsonConsumer
	rt.Consumers["text/x-json"] = jsonConsumer
	rt.DefaultMediaType = openapiRuntime.JSONMime
}

// OrgIDRoundTripper wraps an http.RoundTripper to add the X-Grafana-Org-Id header.
type OrgIDRoundTripper struct {
	underlying http.RoundTripper
	orgID      int64
}

func (t *OrgIDRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// clone the request to avoid modifying the original
	clonedReq := req.Clone(req.Context())

	if t.orgID > 0 {
		clonedReq.Header.Set(client.OrgIDHeader, strconv.FormatInt(t.orgID, 10))
	}

	return t.underlying.RoundTrip(clonedReq)
}

func NewOrgIDRoundTripper(rt http.RoundTripper, orgID int64) *OrgIDRoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &OrgIDRoundTripper{
		underlying: rt,
		orgID:      orgID,
	}
}

type SessionCookieRoundTripper struct {
	underlying        http.RoundTripper
	sessionCookie     string
	sessionCookieFile string
	autoLoginMu       sync.Mutex
	lastAutoLogin     time.Time
	autoLoginCooldown time.Duration
	grafanaURL        string
}

func (t *SessionCookieRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	bodyCopy, err := bufferRequestBody(req)
	if err != nil {
		return nil, err
	}

	loginCheckURL := ""
	if t.grafanaURL != "" {
		loginCheckURL = fmt.Sprintf("%s/api/user", strings.TrimRight(t.grafanaURL, "/"))
	}

	// attempt executes a single HTTP round trip with the latest cookie value
	attempt := func() (*http.Response, error) {
		clonedReq := cloneRequestWithBody(req, bodyCopy)

		cookie := resolveSessionCookie(t.sessionCookie, t.sessionCookieFile)
		// If we were configured with a cookie file but it's missing/empty, try to populate it first.
		if cookie == "" && t.sessionCookieFile != "" {
			if err := t.triggerAutoLogin(clonedReq.Context(), false, loginCheckURL); err == nil {
				cookie = resolveSessionCookie(t.sessionCookie, t.sessionCookieFile)
			} else {
				slog.Debug("Auto-login skipped before first attempt", "error", err)
			}
		}

		if cookie != "" {
			clonedReq.Header.Set("Cookie", formatCookieHeader(cookie))
		}

		return t.underlying.RoundTrip(clonedReq)
	}

	resp, err := attempt()
	if resp == nil || err != nil || (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden) || t.sessionCookieFile == "" {
		return resp, err
	}

	// Auth failure: attempt to refresh the cookie via auto-login, then retry once.
	_ = resp.Body.Close()
	if err := t.triggerAutoLogin(req.Context(), true, loginCheckURL); err != nil {
		return resp, err
	}

	return attempt()
}

func NewSessionCookieRoundTripper(rt http.RoundTripper, sessionCookie, sessionCookieFile, grafanaURL string) *SessionCookieRoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}

	return &SessionCookieRoundTripper{
		underlying:        rt,
		sessionCookie:     sessionCookie,
		sessionCookieFile: sessionCookieFile,
		autoLoginCooldown: 30 * time.Second,
		grafanaURL:        grafanaURL,
	}
}

func bufferRequestBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	// Prefer GetBody when available to avoid consuming the original reader.
	if req.GetBody != nil {
		rc, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}

	data, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}

func cloneRequestWithBody(req *http.Request, body []byte) *http.Request {
	clonedReq := req.Clone(req.Context())
	if body != nil {
		clonedReq.Body = io.NopCloser(bytes.NewReader(body))
		clonedReq.ContentLength = int64(len(body))
	}
	return clonedReq
}

func (t *SessionCookieRoundTripper) triggerAutoLogin(ctx context.Context, force bool, loginURL string) error {
	if t.sessionCookieFile == "" {
		return fmt.Errorf("auto-login requires a session cookie file path")
	}
	if t.grafanaURL == "" {
		return fmt.Errorf("auto-login requires Grafana URL")
	}

	t.autoLoginMu.Lock()
	defer t.autoLoginMu.Unlock()

	if !force && time.Since(t.lastAutoLogin) < t.autoLoginCooldown {
		return fmt.Errorf("auto-login recently attempted")
	}

	t.lastAutoLogin = time.Now()

	if err := t.runBrowserLogin(ctx, loginURL); err != nil {
		return fmt.Errorf("browser login failed: %w", err)
	}

	return nil
}

func (t *SessionCookieRoundTripper) runBrowserLogin(ctx context.Context, loginURL string) error {
	if ctx == nil {
		ctx = context.Background()
	}

	tryCookie := func(cookieHeader, source string) (bool, error) {
		cookieHeader = strings.TrimSpace(cookieHeader)
		if cookieHeader == "" {
			return false, nil
		}

		valid, err := t.validateCookie(ctx, loginURL, cookieHeader)
		if err != nil {
			return false, fmt.Errorf("validate %s cookie: %w", source, err)
		}
		if !valid {
			slog.Debug("Cookie rejected by Grafana", "source", source)
			return false, nil
		}

		if err := saveCookieToFile(t.sessionCookieFile, cookieHeader); err != nil {
			return false, err
		}
		t.sessionCookie = cookieHeader
		return true, nil
	}

	// First attempt: use get-cookie CLI if available (primary path).
	if cookieHeader, err := loadCookieWithGetCookie(t.grafanaURL); err == nil && cookieHeader != "" {
		if ok, err := tryCookie(cookieHeader, "get-cookie"); err != nil {
			return err
		} else if ok {
			return nil
		}
	}

	// Second attempt: try existing browser cookies without user interaction via kooky.
	if cookieHeader, err := loadCookieFromBrowser(t.grafanaURL); err == nil && cookieHeader != "" {
		if ok, err := tryCookie(cookieHeader, "browser"); err != nil {
			return err
		} else if ok {
			return nil
		}
	}

	// Fallback: prompt user to log in, then re-read cookies.
	target := t.grafanaURL
	if target == "" && loginURL != "" {
		target = loginURL
	}
	_ = openDefaultBrowser(target)
	fmt.Printf("\nBrowser opened to %s. Please log in, then press Enter to continue (we will re-read your browser cookies).\n", target)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

	cookieHeader, err := loadCookieFromBrowser(t.grafanaURL)
	if err != nil {
		return fmt.Errorf("could not read cookies from browser via kooky: %w", err)
	}
	cookieHeader = strings.TrimSpace(cookieHeader)
	if cookieHeader == "" {
		return fmt.Errorf("no browser cookies found for Grafana; please ensure you are logged in")
	}

	fmt.Println("\nCaptured Cookie header:")
	fmt.Println(cookieHeader)
	fmt.Print("\nPress Enter to save this cookie to file and retry the request, or Ctrl+C to abort: ")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')

	if ok, err := tryCookie(cookieHeader, "interactive-kooky"); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("browser cookie was rejected by Grafana")
	}

	return nil
}

func (t *SessionCookieRoundTripper) validateCookie(ctx context.Context, loginURL, cookieHeader string) (bool, error) {
	if loginURL == "" {
		return true, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loginURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Cookie", formatCookieHeader(cookieHeader))

	resp, err := t.underlying.RoundTrip(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	}
	if resp.StatusCode >= 400 {
		return false, fmt.Errorf("cookie validation request failed: %s", resp.Status)
	}

	return true, nil
}

func saveCookieToFile(path, cookieHeader string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create cookie dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(cookieHeader), 0o600); err != nil {
		return fmt.Errorf("write cookie file: %w", err)
	}
	slog.Info("Saved session cookie to file", "file", path)
	return nil
}

func loadCookieFromBrowser(grafanaURL string) (string, error) {
	u, err := url.Parse(grafanaURL)
	if err != nil {
		return "", fmt.Errorf("parse grafana url: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("grafana url missing hostname")
	}

	// If user points directly at a browser cookie DB file, prefer it.
	if cookieFile := strings.TrimSpace(os.Getenv(grafanaBrowserCookiesFile)); cookieFile != "" {
		cookies, err := chrome.ReadCookies(context.Background(), cookieFile, kooky.Domain(host))
		if err != nil {
			slog.Debug("Failed to read cookies from explicit browser file, falling back to auto-discovery", "file", cookieFile, "error", err)
		} else if len(cookies) > 0 {
			return formatCookieList(cookies), nil
		} else {
			slog.Debug("No cookies found in explicit browser file, falling back to auto-discovery", "file", cookieFile)
		}
	}

	cookies, err := kooky.ReadCookies(context.Background(), kooky.Domain(host))
	if err != nil {
		return "", fmt.Errorf("read browser cookies: %w", err)
	}

	if len(cookies) == 0 {
		return "", fmt.Errorf("no browser cookies found for host %s", host)
	}

	return formatCookieList(cookies), nil
}

func formatCookieList(cookies []*kooky.Cookie) string {
	var parts []string
	for _, c := range cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(parts, "; ")
}

func loadCookieWithGetCookie(grafanaURL string) (string, error) {
	u, err := url.Parse(grafanaURL)
	if err != nil {
		return "", fmt.Errorf("parse grafana url: %w", err)
	}

	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("grafana url missing hostname")
	}

	// get-cookie "%" <domain> --output json
	cmd := exec.Command("get-cookie", "%", host, "--output", "json")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("get-cookie command failed: %w", err)
	}

	lines := strings.Split(string(output), "\n")
	var filtered []string
	for _, l := range lines {
		if strings.HasPrefix(l, "[dotenv") {
			continue
		}
		if strings.TrimSpace(l) != "" {
			filtered = append(filtered, l)
		}
	}

	var cookies []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal([]byte(strings.Join(filtered, "\n")), &cookies); err != nil {
		return "", fmt.Errorf("parse get-cookie output: %w", err)
	}

	if len(cookies) == 0 {
		return "", fmt.Errorf("get-cookie returned no cookies")
	}

	var parts []string
	for _, c := range cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}
	return strings.Join(parts, "; "), nil
}

func openDefaultBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	return cmd.Start()
}

// Gets info from environment
func extractKeyGrafanaInfoFromEnv() (url, apiKey string, auth *url.Userinfo, orgId int64, sessionCookie, sessionCookieFile string) {
	url, apiKey = urlAndAPIKeyFromEnv()
	if url == "" {
		url = defaultGrafanaURL
	}
	auth = userAndPassFromEnv()
	orgId = orgIdFromEnv()
	sessionCookieFile = os.Getenv(grafanaSessionCookieFileEnv)
	sessionCookie = sessionCookieFromEnv()
	return
}

// Tries to get grafana info from a request.
// Gets info from environment if it can't get it from request
func extractKeyGrafanaInfoFromReq(req *http.Request) (grafanaUrl, apiKey string, auth *url.Userinfo, orgId int64, sessionCookie, sessionCookieFile string) {
	eUrl, eApiKey, eAuth, eOrgId, eSessionCookie, eSessionCookieFile := extractKeyGrafanaInfoFromEnv()
	username, password, _ := req.BasicAuth()

	grafanaUrl, apiKey = urlAndAPIKeyFromHeaders(req)
	// If anything is missing, check if we can get it from the environment
	if grafanaUrl == "" {
		grafanaUrl = eUrl
	}

	if apiKey == "" {
		apiKey = eApiKey
	}

	// Use environment configured auth if nothing was passed in request
	if username == "" && password == "" {
		auth = eAuth
	} else {
		auth = url.UserPassword(username, password)
	}

	// extract org ID from header, fall back to environment
	orgId = orgIdFromHeaders(req)
	if orgId == 0 {
		orgId = eOrgId
	}

	sessionCookie = extractSessionCookieFromRequest(req)
	if sessionCookie == "" {
		sessionCookie = eSessionCookie
	}

	sessionCookieFile = eSessionCookieFile

	return
}

func extractSessionCookieFromRequest(req *http.Request) string {
	if cookie, err := req.Cookie("grafana_session"); err == nil {
		return cookie.Value
	}
	return ""
}

// ExtractGrafanaInfoFromEnv is a StdioContextFunc that extracts Grafana configuration from environment variables.
// It reads GRAFANA_URL and GRAFANA_SERVICE_ACCOUNT_TOKEN (or deprecated GRAFANA_API_KEY) environment variables and adds the configuration to the context for use by Grafana clients.
var ExtractGrafanaInfoFromEnv server.StdioContextFunc = func(ctx context.Context) context.Context {
	u, apiKey, basicAuth, orgID, sessionCookie, sessionCookieFile := extractKeyGrafanaInfoFromEnv()
	parsedURL, err := url.Parse(u)
	if err != nil {
		panic(fmt.Errorf("invalid Grafana URL %s: %w", u, err))
	}

	slog.Info("Using Grafana configuration",
		"url", parsedURL.Redacted(),
		"api_key_set", apiKey != "",
		"basic_auth_set", basicAuth != nil,
		"org_id", orgID,
		"session_cookie_set", sessionCookie != "",
		"session_cookie_file_set", sessionCookieFile != "")

	// Get existing config or create a new one.
	// This will respect the existing debug flag, if set.
	config := GrafanaConfigFromContext(ctx)
	config.URL = u
	config.APIKey = apiKey
	config.BasicAuth = basicAuth
	config.OrgID = orgID
	config.SessionCookie = sessionCookie
	config.SessionCookieFile = sessionCookieFile
	return WithGrafanaConfig(ctx, config)
}

// httpContextFunc is a function that can be used as a `server.HTTPContextFunc` or a
// `server.SSEContextFunc`. It is necessary because, while the two types are functionally
// identical, they have distinct types and cannot be passed around interchangeably.
type httpContextFunc func(ctx context.Context, req *http.Request) context.Context

// ExtractGrafanaInfoFromHeaders is a HTTPContextFunc that extracts Grafana configuration from HTTP request headers.
// It reads X-Grafana-URL and X-Grafana-API-Key headers, falling back to environment variables if headers are not present.
var ExtractGrafanaInfoFromHeaders httpContextFunc = func(ctx context.Context, req *http.Request) context.Context {
	u, apiKey, basicAuth, orgID, sessionCookie, sessionCookieFile := extractKeyGrafanaInfoFromReq(req)

	// Get existing config or create a new one.
	// This will respect the existing debug flag, if set.
	config := GrafanaConfigFromContext(ctx)
	config.URL = u
	config.APIKey = apiKey
	config.BasicAuth = basicAuth
	config.OrgID = orgID
	config.SessionCookie = sessionCookie
	config.SessionCookieFile = sessionCookieFile
	return WithGrafanaConfig(ctx, config)
}

// WithOnBehalfOfAuth adds the Grafana access token and user token to the Grafana config.
// These tokens enable on-behalf-of authentication in Grafana Cloud, allowing the MCP server to act on behalf of a specific user with their permissions.
func WithOnBehalfOfAuth(ctx context.Context, accessToken, userToken string) (context.Context, error) {
	if accessToken == "" || userToken == "" {
		return nil, fmt.Errorf("neither accessToken nor userToken can be empty")
	}
	cfg := GrafanaConfigFromContext(ctx)
	cfg.AccessToken = accessToken
	cfg.IDToken = userToken
	return WithGrafanaConfig(ctx, cfg), nil
}

// MustWithOnBehalfOfAuth adds the access and user tokens to the context, panicking if either are empty.
// This is a convenience wrapper around WithOnBehalfOfAuth for cases where token validation has already occurred.
func MustWithOnBehalfOfAuth(ctx context.Context, accessToken, userToken string) context.Context {
	ctx, err := WithOnBehalfOfAuth(ctx, accessToken, userToken)
	if err != nil {
		panic(err)
	}
	return ctx
}

type grafanaClientKey struct{}

func makeBasePath(path string) string {
	return strings.Join([]string{strings.TrimRight(path, "/"), "api"}, "/")
}

// NewGrafanaClient creates a Grafana client with the provided URL and API key.
// The client is automatically configured with the correct HTTP scheme, debug settings from context, custom TLS configuration if present, and OpenTelemetry instrumentation for distributed tracing.
func NewGrafanaClient(ctx context.Context, grafanaURL, apiKey string, auth *url.Userinfo, orgId int64) *client.GrafanaHTTPAPI {
	cfg := client.DefaultTransportConfig()

	var parsedURL *url.URL
	var err error

	if grafanaURL == "" {
		grafanaURL = defaultGrafanaURL
	}

	parsedURL, err = url.Parse(grafanaURL)
	if err != nil {
		panic(fmt.Errorf("invalid Grafana URL: %w", err))
	}
	cfg.Host = parsedURL.Host
	cfg.BasePath = makeBasePath(parsedURL.Path)

	// The Grafana client will always prefer HTTPS even if the URL is HTTP,
	// so we need to limit the schemes to HTTP if the URL is HTTP.
	if parsedURL.Scheme == "http" {
		cfg.Schemes = []string{"http"}
	}

	config := GrafanaConfigFromContext(ctx)

	if !hasSessionCookie(config.SessionCookie, config.SessionCookieFile) {
		if apiKey != "" {
			cfg.APIKey = apiKey
		}

		if auth != nil {
			cfg.BasicAuth = auth
		}
	}

	cfg.Debug = config.Debug

	if config.OrgID > 0 {
		cfg.OrgID = config.OrgID
	}

	// Configure TLS if custom TLS configuration is provided
	if tlsConfig := config.TLSConfig; tlsConfig != nil {
		tlsCfg, err := tlsConfig.CreateTLSConfig()
		if err != nil {
			panic(fmt.Errorf("failed to create TLS config: %w", err))
		}
		cfg.TLSConfig = tlsCfg
		slog.Debug("Using custom TLS configuration",
			"cert_file", tlsConfig.CertFile,
			"ca_file", tlsConfig.CAFile,
			"skip_verify", tlsConfig.SkipVerify)
	}

	// Determine timeout - use config value if set, otherwise use default
	timeout := config.Timeout
	if timeout == 0 {
		timeout = DefaultGrafanaClientTimeout
	}

	slog.Debug("Creating Grafana client", "url", parsedURL.Redacted(), "api_key_set", apiKey != "", "basic_auth_set", config.BasicAuth != nil, "org_id", cfg.OrgID, "timeout", timeout, "session_cookie_set", hasSessionCookie(config.SessionCookie, config.SessionCookieFile))
	grafanaClient := client.NewHTTPClientWithConfig(strfmt.Default, cfg)
	if rt, ok := grafanaClient.Transport.(*httptransport.Runtime); ok {
		ensureJSONConsumers(rt)
	}
	slog.Debug("Grafana client created, wrapping transport")

	v := reflect.ValueOf(grafanaClient.Transport)
	if v.Kind() == reflect.Ptr && !v.IsNil() {
		runtimeStruct := v.Elem()
		if runtimeStruct.Kind() == reflect.Struct {
			transportField := runtimeStruct.FieldByName("Transport")
			if transportField.IsValid() && transportField.CanSet() {
				if existingTransport, ok := transportField.Interface().(http.RoundTripper); ok {
					slog.Debug("Got existing transport, wrapping it", "type", fmt.Sprintf("%T", existingTransport))
					wrapped := wrapWithSessionCookie(existingTransport, config.SessionCookie, config.SessionCookieFile, grafanaURL)
					wrapped = wrapWithUserAgent(wrapped)
					wrapped = otelhttp.NewTransport(wrapped)

					transportField.Set(reflect.ValueOf(wrapped))
					slog.Debug("Successfully wrapped public Transport field")
				}
			}

			clientField := runtimeStruct.FieldByName("client")
			if clientField.IsValid() {
				slog.Debug("Found internal client field, attempting to wrap its transport")

				clientFieldPtr := reflect.NewAt(clientField.Type(), unsafe.Pointer(clientField.UnsafeAddr()))
				clientValue := clientFieldPtr.Elem()

				if clientValue.Kind() == reflect.Ptr && clientValue.IsNil() {
					slog.Debug("Internal client field is nil, creating HTTP client with wrapped transport")

					wrappedTransport := transportField.Interface().(http.RoundTripper)

					newClient := &http.Client{
						Transport: wrappedTransport,
						Timeout:   timeout,
					}

					clientValue.Set(reflect.ValueOf(newClient))
					slog.Debug("Successfully created and set internal HTTP client with wrapped transport")
				} else if clientValue.Kind() == reflect.Ptr && !clientValue.IsNil() {
					if httpClient, ok := clientValue.Interface().(*http.Client); ok {
						slog.Debug("Got existing internal HTTP client, wrapping its transport", "type", fmt.Sprintf("%T", httpClient.Transport))

						existingTransport := httpClient.Transport
						if existingTransport == nil {
							existingTransport = http.DefaultTransport
						}

						wrapped := wrapWithSessionCookie(existingTransport, config.SessionCookie, config.SessionCookieFile, grafanaURL)
						wrapped = wrapWithUserAgent(wrapped)
						wrapped = otelhttp.NewTransport(wrapped)

						httpClient.Transport = wrapped
						slog.Debug("Successfully wrapped existing internal HTTP client transport")
					}
				}
			}
		}
	}

	return grafanaClient
}

// ExtractGrafanaClientFromEnv is a StdioContextFunc that creates and injects a Grafana client into the context.
// It uses configuration from GRAFANA_URL, GRAFANA_SERVICE_ACCOUNT_TOKEN (or deprecated GRAFANA_API_KEY), GRAFANA_USERNAME/PASSWORD environment variables to initialize
// the client with proper authentication.
var ExtractGrafanaClientFromEnv server.StdioContextFunc = func(ctx context.Context) context.Context {
	// Extract transport config from env vars
	grafanaURL, apiKey := urlAndAPIKeyFromEnv()
	if grafanaURL == "" {
		grafanaURL = defaultGrafanaURL
	}
	auth := userAndPassFromEnv()
	orgId := orgIdFromEnv()
	grafanaClient := NewGrafanaClient(ctx, grafanaURL, apiKey, auth, orgId)
	return WithGrafanaClient(ctx, grafanaClient)
}

// ExtractGrafanaClientFromHeaders is a HTTPContextFunc that creates and injects a Grafana client into the context.
// It prioritizes configuration from HTTP headers (X-Grafana-URL, X-Grafana-API-Key) over environment variables for multi-tenant scenarios.
var ExtractGrafanaClientFromHeaders httpContextFunc = func(ctx context.Context, req *http.Request) context.Context {
	// Extract transport config from request headers, and set it on the context.
	u, apiKey, basicAuth, orgId, _, _ := extractKeyGrafanaInfoFromReq(req)
	slog.Debug("Creating Grafana client", "url", u, "api_key_set", apiKey != "", "basic_auth_set", basicAuth != nil)

	grafanaClient := NewGrafanaClient(ctx, u, apiKey, basicAuth, orgId)
	return WithGrafanaClient(ctx, grafanaClient)
}

// WithGrafanaClient sets the Grafana client in the context.
// The client can be retrieved using GrafanaClientFromContext and will be used by all Grafana-related tools in the MCP server.
func WithGrafanaClient(ctx context.Context, client *client.GrafanaHTTPAPI) context.Context {
	return context.WithValue(ctx, grafanaClientKey{}, client)
}

// GrafanaClientFromContext retrieves the Grafana client from the context.
// Returns nil if no client has been set, which tools should handle gracefully with appropriate error messages.
func GrafanaClientFromContext(ctx context.Context) *client.GrafanaHTTPAPI {
	c, ok := ctx.Value(grafanaClientKey{}).(*client.GrafanaHTTPAPI)
	if !ok {
		return nil
	}
	return c
}

type incidentClientKey struct{}

// ExtractIncidentClientFromEnv is a StdioContextFunc that creates and injects a Grafana Incident client into the context.
// It configures the client using environment variables and applies any custom TLS settings from the context.
var ExtractIncidentClientFromEnv server.StdioContextFunc = func(ctx context.Context) context.Context {
	grafanaURL, apiKey := urlAndAPIKeyFromEnv()
	if grafanaURL == "" {
		grafanaURL = defaultGrafanaURL
	}
	incidentURL := fmt.Sprintf("%s/api/plugins/grafana-irm-app/resources/api/v1/", grafanaURL)
	parsedURL, err := url.Parse(incidentURL)
	if err != nil {
		panic(fmt.Errorf("invalid incident URL %s: %w", incidentURL, err))
	}

	config := GrafanaConfigFromContext(ctx)
	if hasSessionCookie(config.SessionCookie, config.SessionCookieFile) {
		apiKey = ""
	}

	slog.Debug("Creating Incident client", "url", parsedURL.Redacted(), "api_key_set", apiKey != "", "session_cookie_set", hasSessionCookie(config.SessionCookie, config.SessionCookieFile))
	client := incident.NewClient(incidentURL, apiKey)

	// Configure custom TLS if available
	var transport http.RoundTripper = http.DefaultTransport
	if tlsConfig := config.TLSConfig; tlsConfig != nil {
		if t, err := tlsConfig.HTTPTransport(http.DefaultTransport.(*http.Transport)); err != nil {
			slog.Error("Failed to create custom transport for incident client, using default", "error", err)
		} else {
			transport = t
		}
	}
	orgIDWrapped := NewOrgIDRoundTripper(transport, config.OrgID)
	sessionWrapped := wrapWithSessionCookie(orgIDWrapped, config.SessionCookie, config.SessionCookieFile, config.URL)
	client.HTTPClient.Transport = wrapWithUserAgent(sessionWrapped)

	return context.WithValue(ctx, incidentClientKey{}, client)
}

// ExtractIncidentClientFromHeaders is a HTTPContextFunc that creates and injects a Grafana Incident client into the context.
// It uses HTTP headers for configuration with environment variable fallbacks, enabling per-request incident management configuration.
var ExtractIncidentClientFromHeaders httpContextFunc = func(ctx context.Context, req *http.Request) context.Context {
	grafanaURL, apiKey, _, orgID, sessionCookie, sessionCookieFile := extractKeyGrafanaInfoFromReq(req)
	incidentURL := fmt.Sprintf("%s/api/plugins/grafana-irm-app/resources/api/v1/", grafanaURL)

	if hasSessionCookie(sessionCookie, sessionCookieFile) {
		apiKey = ""
	}

	client := incident.NewClient(incidentURL, apiKey)

	config := GrafanaConfigFromContext(ctx)
	// Configure custom TLS if available
	var transport http.RoundTripper = http.DefaultTransport
	if tlsConfig := config.TLSConfig; tlsConfig != nil {
		if t, err := tlsConfig.HTTPTransport(http.DefaultTransport.(*http.Transport)); err != nil {
			slog.Error("Failed to create custom transport for incident client, using default", "error", err)
		} else {
			transport = t
		}
	}
	orgIDWrapped := NewOrgIDRoundTripper(transport, orgID)
	sessionWrapped := wrapWithSessionCookie(orgIDWrapped, sessionCookie, sessionCookieFile, grafanaURL)
	client.HTTPClient.Transport = wrapWithUserAgent(sessionWrapped)

	return context.WithValue(ctx, incidentClientKey{}, client)
}

// WithIncidentClient sets the Grafana Incident client in the context.
// This client is used for managing incidents, activities, and other IRM (Incident Response Management) operations.
func WithIncidentClient(ctx context.Context, client *incident.Client) context.Context {
	return context.WithValue(ctx, incidentClientKey{}, client)
}

// IncidentClientFromContext retrieves the Grafana Incident client from the context.
// Returns nil if no client has been set, indicating that incident management features are not available.
func IncidentClientFromContext(ctx context.Context) *incident.Client {
	c, ok := ctx.Value(incidentClientKey{}).(*incident.Client)
	if !ok {
		return nil
	}
	return c
}

// ComposeStdioContextFuncs composes multiple StdioContextFuncs into a single one.
// Functions are applied in order, allowing each to modify the context before passing it to the next.
func ComposeStdioContextFuncs(funcs ...server.StdioContextFunc) server.StdioContextFunc {
	return func(ctx context.Context) context.Context {
		for _, f := range funcs {
			ctx = f(ctx)
		}
		return ctx
	}
}

// ComposeSSEContextFuncs composes multiple SSEContextFuncs into a single one.
// This enables chaining of context modifications for Server-Sent Events transport, such as extracting headers and setting up clients.
func ComposeSSEContextFuncs(funcs ...httpContextFunc) server.SSEContextFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		for _, f := range funcs {
			ctx = f(ctx, req)
		}
		return ctx
	}
}

// ComposeHTTPContextFuncs composes multiple HTTPContextFuncs into a single one.
// This enables chaining of context modifications for HTTP transport, allowing modular setup of authentication, clients, and configuration.
func ComposeHTTPContextFuncs(funcs ...httpContextFunc) server.HTTPContextFunc {
	return func(ctx context.Context, req *http.Request) context.Context {
		for _, f := range funcs {
			ctx = f(ctx, req)
		}
		return ctx
	}
}

// ComposedStdioContextFunc returns a StdioContextFunc that comprises all predefined StdioContextFuncs.
// It sets up the complete context for stdio transport including Grafana configuration, client initialization from environment variables, and incident management support.
func ComposedStdioContextFunc(config GrafanaConfig) server.StdioContextFunc {
	return ComposeStdioContextFuncs(
		func(ctx context.Context) context.Context {
			return WithGrafanaConfig(ctx, config)
		},
		ExtractGrafanaInfoFromEnv,
		ExtractGrafanaClientFromEnv,
		ExtractIncidentClientFromEnv,
	)
}

// ComposedSSEContextFunc returns a SSEContextFunc that comprises all predefined SSEContextFuncs.
// It sets up the complete context for SSE transport, extracting configuration from HTTP headers with environment variable fallbacks.
func ComposedSSEContextFunc(config GrafanaConfig) server.SSEContextFunc {
	return ComposeSSEContextFuncs(
		func(ctx context.Context, req *http.Request) context.Context {
			return WithGrafanaConfig(ctx, config)
		},
		ExtractGrafanaInfoFromHeaders,
		ExtractGrafanaClientFromHeaders,
		ExtractIncidentClientFromHeaders,
	)
}

// ComposedHTTPContextFunc returns a HTTPContextFunc that comprises all predefined HTTPContextFuncs.
// It provides the complete context setup for HTTP transport, including header-based authentication and client configuration.
func ComposedHTTPContextFunc(config GrafanaConfig) server.HTTPContextFunc {
	return ComposeHTTPContextFuncs(
		func(ctx context.Context, req *http.Request) context.Context {
			return WithGrafanaConfig(ctx, config)
		},
		ExtractGrafanaInfoFromHeaders,
		ExtractGrafanaClientFromHeaders,
		ExtractIncidentClientFromHeaders,
	)
}
