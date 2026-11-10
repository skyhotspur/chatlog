package http

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testConfig struct {
	dataDir string
	token   string
	hosts   []string
}

func (c *testConfig) GetHTTPAddr() string           { return "127.0.0.1:5030" }
func (c *testConfig) GetDataDir() string            { return c.dataDir }
func (c *testConfig) GetHTTPToken() string          { return c.token }
func (c *testConfig) GetHTTPAllowedHosts() []string { return c.hosts }

// newTestService lays out: <root>/data/{chatlog.json,db_storage/message/message_0.db,msg/pic.jpg}
// and <root>/outside/secret.txt (must never be reachable or detectable).
func newTestService(t *testing.T, token string, hosts ...string) *Service {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"data/chatlog.json":                        `{"data_key":"SECRETKEY"}`,
		"data/db_storage/message/message_0.db":     "ENCRYPTED-DB",
		"data/db_storage/message/message_0.db-wal": "WAL",
		"data/msg/pic.jpg":                         "JPEGDATA",
		"data/msg/file/report.pdf":                 "PDFDATA",
		"outside/secret.txt":                       "outside",
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return NewService(&testConfig{dataDir: filepath.Join(root, "data"), token: token, hosts: hosts}, nil)
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withHost(h string) reqOpt      { return func(r *http.Request) { r.Host = h } }

func do(s *Service, method, target string, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "http://127.0.0.1:5030/", nil)
	// Set the raw path directly so "../" segments reach the router unnormalised.
	path, query, _ := strings.Cut(target, "?")
	req.URL.Path = path
	req.URL.RawQuery = query
	for _, opt := range opts {
		opt(req)
	}
	w := httptest.NewRecorder()
	s.GetRouter().ServeHTTP(w, req)
	return w
}

func TestDataRouteNeverServesKeysOrDatabases(t *testing.T) {
	s := newTestService(t, "")
	for _, path := range []string{
		"/data/chatlog.json",
		"/data/CHATLOG.JSON",
		"/data/./chatlog.json",
		"/data/msg/../chatlog.json",
		"/data/db_storage/message/message_0.db",
		"/data/db_storage/message/message_0.db-wal",
	} {
		w := do(s, http.MethodGet, path)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403", path, w.Code)
		}
		if body := w.Body.String(); strings.Contains(body, "SECRETKEY") || strings.Contains(body, "ENCRYPTED-DB") {
			t.Errorf("%s: leaked sensitive content: %q", path, body)
		}
	}
}

func TestDataRouteStillServesMedia(t *testing.T) {
	s := newTestService(t, "")
	for path, want := range map[string]string{
		"/data/msg/pic.jpg":         "JPEGDATA",
		"/data/msg/file/report.pdf": "PDFDATA",
	} {
		w := do(s, http.MethodGet, path)
		if w.Code != http.StatusOK || w.Body.String() != want {
			t.Errorf("%s: got %d %q, want 200 %q", path, w.Code, w.Body.String(), want)
		}
	}
}

func TestDataRouteCannotEscapeDataDir(t *testing.T) {
	s := newTestService(t, "")
	for _, path := range []string{"/data/../outside/secret.txt", "/data/../../outside/secret.txt"} {
		w := do(s, http.MethodGet, path)
		if strings.Contains(w.Body.String(), "outside") && w.Code == http.StatusOK {
			t.Errorf("%s: escaped data dir", path)
		}
	}
}

// The 302-vs-404 answer must not reveal whether files outside the data dir exist.
func TestFindPathIsNotAnExistenceOracle(t *testing.T) {
	s := newTestService(t, "")
	for _, key := range []string{"../outside/secret.txt", "../outside/missing.txt", "msg/../../outside/secret.txt"} {
		if p, err := s.findPath("image", key); err == nil {
			t.Errorf("findPath(%q) resolved to %q, want not found", key, p)
		}
	}
	if p, err := s.findPath("image", "msg/pic.jpg"); err != nil || p != "msg/pic.jpg" {
		t.Errorf("findPath for a real media file: got %q, %v", p, err)
	}
}

func TestCORSRejectsForeignOrigins(t *testing.T) {
	s := newTestService(t, "", "nas.lan")

	w := do(s, http.MethodGet, "/data/msg/pic.jpg", withHeader("Origin", "https://evil.example"))
	if w.Code != http.StatusForbidden {
		t.Errorf("foreign origin: got %d, want 403", w.Code)
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("foreign origin got Access-Control-Allow-Origin %q", got)
	}

	for _, origin := range []string{"http://127.0.0.1:5030", "http://localhost:3000", "http://nas.lan:8080"} {
		w := do(s, http.MethodGet, "/data/msg/pic.jpg", withHeader("Origin", origin))
		if w.Code != http.StatusOK {
			t.Errorf("origin %s: got %d, want 200", origin, w.Code)
		}
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Errorf("origin %s: Access-Control-Allow-Origin = %q", origin, got)
		}
	}

	// No Origin header (curl, MCP clients, same-origin navigations): never a wildcard.
	w = do(s, http.MethodGet, "/data/msg/pic.jpg")
	if w.Code != http.StatusOK || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("no origin: got %d, ACAO %q", w.Code, w.Header().Get("Access-Control-Allow-Origin"))
	}
}

// DNS rebinding: an attacker-controlled name resolving to this server.
func TestHostHeaderCheck(t *testing.T) {
	s := newTestService(t, "", "nas.lan")
	cases := map[string]int{
		"127.0.0.1:5030":     http.StatusOK,
		"localhost:5030":     http.StatusOK,
		"192.168.1.10:5030":  http.StatusOK,
		"[::1]:5030":         http.StatusOK,
		"nas.lan:5030":       http.StatusOK,
		"NAS.LAN":            http.StatusOK,
		"attacker.example":   http.StatusForbidden,
		"evil.nas.lan:5030":  http.StatusForbidden,
		"127.0.0.1.evil.com": http.StatusForbidden,
	}
	for host, want := range cases {
		if w := do(s, http.MethodGet, "/health", withHost(host)); w.Code != want {
			t.Errorf("Host %q: got %d, want %d", host, w.Code, want)
		}
	}
}

func TestTokenAuth(t *testing.T) {
	s := newTestService(t, "s3cret")
	const path = "/data/msg/pic.jpg"

	if w := do(s, http.MethodGet, path); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", w.Code)
	}
	if w := do(s, http.MethodGet, path, withHeader("Authorization", "Bearer wrong")); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: got %d, want 401", w.Code)
	}
	if w := do(s, http.MethodPost, "/mcp"); w.Code != http.StatusUnauthorized {
		t.Errorf("MCP without token: got %d, want 401", w.Code)
	}
	if w := do(s, http.MethodGet, "/health"); w.Code != http.StatusOK {
		t.Errorf("/health must stay open for container healthchecks: got %d", w.Code)
	}
	if w := do(s, http.MethodGet, path, withHeader("Authorization", "Bearer s3cret")); w.Code != http.StatusOK {
		t.Errorf("bearer token: got %d, want 200", w.Code)
	}

	// ?token= logs the browser in via an HttpOnly cookie, which then works alone.
	w := do(s, http.MethodGet, path+"?token=s3cret")
	if w.Code != http.StatusOK {
		t.Fatalf("query token: got %d, want 200", w.Code)
	}
	cookie := w.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, tokenCookieName+"=s3cret") || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
		t.Fatalf("unexpected Set-Cookie: %q", cookie)
	}
	if w := do(s, http.MethodGet, path, withHeader("Cookie", tokenCookieName+"=s3cret")); w.Code != http.StatusOK {
		t.Errorf("cookie token: got %d, want 200", w.Code)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:5030": true,
		"localhost:5030": true,
		"[::1]:5030":     true,
		"0.0.0.0:5030":   false,
		":5030":          false,
		"192.168.1.2:80": false,
	}
	for addr, want := range cases {
		if got := isLoopbackAddr(addr); got != want {
			t.Errorf("isLoopbackAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}
