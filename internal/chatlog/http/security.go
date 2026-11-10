package http

import (
	"crypto/subtle"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	tokenCookieName = "chatlog_token"
	tokenQueryName  = "token"
)

// SecurityConfig is optional: configs that do not implement it get the safe
// defaults (no token, only IP/localhost Host headers accepted).
type SecurityConfig interface {
	GetHTTPToken() string
	GetHTTPAllowedHosts() []string
}

func securityOptions(conf Config) (token string, allowedHosts []string) {
	if sc, ok := conf.(SecurityConfig); ok {
		return sc.GetHTTPToken(), sc.GetHTTPAllowedHosts()
	}
	return "", nil
}

// hostname strips the port from a Host header / URL host and lowercases it.
func hostname(hostport string) string {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isAllowedHost accepts IP literals and localhost unconditionally: DNS
// rebinding needs an attacker-controlled *name* to resolve to this server,
// so any other name must be explicitly allowed.
func isAllowedHost(host string, allowed []string) bool {
	if host == "localhost" || net.ParseIP(host) != nil {
		return true
	}
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "*" || (a != "" && a == host) {
			return true
		}
	}
	return false
}

func hostCheckMiddleware(allowed []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAllowedHost(hostname(c.Request.Host), allowed) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "host not allowed; add it to http_allowed_hosts (CHATLOG_HTTP_ALLOWED_HOSTS)",
			})
			return
		}
		c.Next()
	}
}

// isAllowedOrigin: same-origin, loopback pages (local tools on another port)
// and explicitly allowed hosts. Arbitrary websites must never be able to read
// chat data through the visitor's browser.
func isAllowedOrigin(origin, requestHost string, allowed []string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	if strings.EqualFold(u.Host, requestHost) {
		return true
	}
	host := hostname(u.Host)
	if isLoopbackHost(host) {
		return true
	}
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "*" || (a != "" && a == host) {
			return true
		}
	}
	return false
}

func corsMiddleware(allowed []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		// Stops other sites from embedding media (<img>/<video>) served here.
		h.Set("Cross-Origin-Resource-Policy", "same-site")

		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			c.Next()
			return
		}
		h.Add("Vary", "Origin")
		if !isAllowedOrigin(origin, c.Request.Host, allowed) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "origin not allowed"})
			return
		}

		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Access-Control-Allow-Credentials", "true")
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Accept, Authorization, Content-Type, X-CSRF-Token, Mcp-Session-Id, Mcp-Protocol-Version")
		h.Set("Access-Control-Expose-Headers", "Mcp-Session-Id")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func tokenEqual(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// tokenMiddleware is a no-op when no token is configured. A valid ?token= on
// a page load is turned into an HttpOnly cookie so the bundled web UI and the
// media links it renders keep working without carrying the token in every URL.
func tokenMiddleware(token string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if token == "" || c.Request.URL.Path == "/health" || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		if auth := c.Request.Header.Get("Authorization"); len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			if tokenEqual(strings.TrimSpace(auth[7:]), token) {
				c.Next()
				return
			}
		}
		if tokenEqual(c.Query(tokenQueryName), token) {
			c.SetSameSite(http.SameSiteStrictMode)
			c.SetCookie(tokenCookieName, token, 0, "/", "", false, true)
			c.Next()
			return
		}
		if cookie, err := c.Cookie(tokenCookieName); err == nil && tokenEqual(cookie, token) {
			c.Next()
			return
		}

		c.Header("WWW-Authenticate", `Bearer realm="chatlog"`)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized; send 'Authorization: Bearer <token>' or open /?token=<token>",
		})
	}
}

// cleanRelPath confines a request path to the data dir: rooting it before
// Clean makes any ".." collapse at the root instead of escaping.
func cleanRelPath(rel string) string {
	sep := string(filepath.Separator)
	return strings.TrimPrefix(filepath.Clean(sep+filepath.FromSlash(rel)), sep)
}

var sensitiveDataSuffixes = []string{".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3"}

// isSensitiveDataPath reports files under the data dir that must never be
// served: chatlog.json holds the decryption keys and the databases are the
// (encrypted) chat history itself; key + database is a full compromise.
func isSensitiveDataPath(rel string) bool {
	rel = strings.ToLower(filepath.ToSlash(rel))
	if rel == "chatlog.json" {
		return true
	}
	for _, suffix := range sensitiveDataSuffixes {
		if strings.HasSuffix(rel, suffix) {
			return true
		}
	}
	return false
}

// isLoopbackAddr reports whether a listen address is only reachable locally.
func isLoopbackAddr(addr string) bool {
	return isLoopbackHost(hostname(addr))
}
