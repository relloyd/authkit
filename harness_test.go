package authkit_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/relloyd/authkit"
	"github.com/relloyd/authkit/internal/authtest"
	"github.com/relloyd/authkit/sqlitestore"
)

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// app is a small application wired to a Kit, served over TLS so that the
// Secure, __Host- prefixed cookies behave as they do in production.
type app struct {
	t      *testing.T
	srv    *httptest.Server
	kit    *authkit.Kit
	store  *sqlitestore.Store
	db     *sql.DB
	clock  *clock
	issuer *authtest.Issuer
	github *authtest.GitHub
	logs   *strings.Builder
}

func newStore(t *testing.T) (*sqlitestore.Store, *sql.DB) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "test.db") + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := sqlitestore.New(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	return store, db
}

// newApp starts an app offering the fake Google and GitHub. tweak may edit
// the Config before the Kit is built.
func newApp(t *testing.T, tweak func(cfg *authkit.Config, a *app)) *app {
	t.Helper()
	a := &app{t: t, clock: &clock{t: time.Now()}, logs: &strings.Builder{}}
	a.store, a.db = newStore(t)
	a.issuer = authtest.NewIssuer(t)
	a.github = authtest.NewGitHub(t)

	var handler http.Handler
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(a.srv.Close)

	google, err := authkit.NewOIDC(authkit.OIDCConfig{
		Name: "google", Label: "Google", Issuer: a.issuer.URL(),
		ClientID: authtest.ClientID, ClientSecret: authtest.ClientSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	gh, err := authkit.NewGitHub(authkit.GitHubConfig{
		ClientID: authtest.ClientID, ClientSecret: authtest.ClientSecret,
		WebURL: a.github.Server.URL, APIURL: a.github.Server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := authkit.Config{
		Store:         a.store,
		BaseURL:       a.srv.URL,
		Providers:     []authkit.Provider{google, gh},
		SignUp:        authkit.SignUp{Mode: authkit.SignUpOpen},
		RatePerMinute: -1,
		Now:           a.clock.Now,
		Logger:        slog.New(slog.NewTextHandler(&lockedWriter{w: a.logs}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tweak != nil {
		tweak(&cfg, a)
	}
	a.kit, err = authkit.New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := authkit.UserFrom(r.Context())
		if !ok {
			_, _ = fmt.Fprint(w, "nobody")
			return
		}
		_, _ = fmt.Fprintf(w, "user=%d email=%s roles=%s", u.ID, u.Email, strings.Join(u.Roles, ","))
	})
	mux := http.NewServeMux()
	a.kit.Register(mux)
	mux.Handle("GET /{$}", a.kit.LoadUser(whoami))
	mux.Handle("GET /login", a.kit.LoadUser(whoami))
	mux.Handle("GET /app", a.kit.RequireUser(whoami))
	mux.Handle("GET /app/{rest...}", a.kit.RequireUser(whoami))
	mux.Handle("GET /admin", a.kit.RequireRole("admin")(whoami))
	mux.Handle("/api/thing", a.kit.RequireUser(whoami))
	mux.Handle("GET /api/admin", a.kit.RequireRole("admin")(whoami))
	handler = mux
	return a
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// browser is an HTTP client with its own cookie jar that records every hop
// of a redirect chain.
type browser struct {
	t      *testing.T
	a      *app
	client *http.Client
}

func (a *app) browser() *browser {
	a.t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		a.t.Fatal(err)
	}
	c := *a.srv.Client() // a copy: trusts the test server's certificate, own jar
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{t: a.t, a: a, client: &c}
}

// hop is one response in a redirect chain.
type hop struct {
	URL    *url.URL
	Status int
	Header http.Header
	Body   string
}

// do sends the request and follows redirects by hand, returning every hop.
func (b *browser) do(req *http.Request) []hop {
	b.t.Helper()
	var hops []hop
	for range 10 {
		resp, err := b.client.Do(req)
		if err != nil {
			b.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		hops = append(hops, hop{URL: req.URL, Status: resp.StatusCode, Header: resp.Header, Body: string(body)})
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode > 399 || loc == "" {
			return hops
		}
		next, err := req.URL.Parse(loc)
		if err != nil {
			b.t.Fatal(err)
		}
		req, _ = http.NewRequest(http.MethodGet, next.String(), nil)
		req.Header.Set("Accept", "text/html")
	}
	b.t.Fatal("too many redirects")
	return nil
}

// page loads a path the way a browser navigation does.
func (b *browser) page(path string) []hop {
	b.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.a.srv.URL+path, nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	return b.do(req)
}

// api calls a path the way fetch() does.
func (b *browser) api(method, path string, headers ...string) hop {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.a.srv.URL+path, nil)
	req.Header.Set("Accept", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	hops := b.do(req)
	return hops[len(hops)-1]
}

// login runs a whole login and returns the hops: login, provider, callback,
// then wherever the callback sent the browser.
func (b *browser) login(provider, returnTo string) []hop {
	b.t.Helper()
	path := "/auth/login/" + provider
	if returnTo != "" {
		path += "?return=" + url.QueryEscape(returnTo)
	}
	return b.page(path)
}

// mustLogin logs in and fails the test unless it ends signed in.
func (b *browser) mustLogin(provider string) {
	b.t.Helper()
	hops := b.login(provider, "/app")
	if l := last(hops); l.Status != http.StatusOK || !strings.HasPrefix(l.Body, "user=") {
		b.t.Fatalf("login via %s did not sign in: ended at %s with %d %q\nlogs:\n%s", provider, l.URL, l.Status, l.Body, b.a.logs)
	}
}

// loginError logs in and returns the ?error= code the login page received.
func (b *browser) loginError(provider string) string {
	b.t.Helper()
	l := last(b.login(provider, "/app"))
	if l.URL.Path != "/login" {
		b.t.Fatalf("login did not fail: ended at %s (%d %q)", l.URL, l.Status, l.Body)
	}
	if got := b.api("GET", "/auth/me"); got.Status != http.StatusUnauthorized {
		b.t.Fatalf("a failed login left a session: /auth/me = %d", got.Status)
	}
	return l.URL.Query().Get("error")
}

func last(hops []hop) hop { return hops[len(hops)-1] }

// callbackHop returns the hop that hit /auth/callback/.
func callbackHop(t *testing.T, hops []hop) hop {
	t.Helper()
	for _, h := range hops {
		if strings.HasPrefix(h.URL.Path, "/auth/callback/") {
			return h
		}
	}
	t.Fatal("no callback in the redirect chain")
	return hop{}
}

func (a *app) count(table string) int {
	a.t.Helper()
	var n int
	if err := a.db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		a.t.Fatal(err)
	}
	return n
}
