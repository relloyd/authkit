package authkit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/relloyd/authkit"
	"github.com/relloyd/authkit/internal/authtest"
)

func (a *app) url() *url.URL {
	u, _ := url.Parse(a.srv.URL)
	return u
}

func TestSessionExpiry(t *testing.T) {
	day := 24 * time.Hour
	signedIn := func(b *browser) bool {
		return b.api("GET", "/api/thing").Status == http.StatusOK
	}

	t.Run("idle timeout", func(t *testing.T) {
		a := newApp(t, nil)
		b := a.browser()
		b.mustLogin("google")
		a.clock.Advance(29 * day)
		if !signedIn(b) {
			t.Fatal("signed out before the idle timeout")
		}
		// That request counted as activity, so the 30 days start again.
		a.clock.Advance(29 * day)
		if !signedIn(b) {
			t.Fatal("activity did not extend the session")
		}
		a.clock.Advance(31 * day)
		if signedIn(b) {
			t.Fatal("still signed in after 31 idle days")
		}
		if n := a.count("authkit_sessions"); n != 0 {
			t.Errorf("expired session row was not deleted")
		}
	})

	t.Run("absolute timeout", func(t *testing.T) {
		a := newApp(t, nil)
		b := a.browser()
		b.mustLogin("google")
		// Active every 20 days, so never idle, but 100 days old in the end.
		for range 4 {
			a.clock.Advance(20 * day)
			if !signedIn(b) {
				t.Fatal("signed out before the absolute timeout")
			}
		}
		a.clock.Advance(20 * day)
		if signedIn(b) {
			t.Fatal("still signed in 100 days after sign-in")
		}
	})

	t.Run("configured lifetimes", func(t *testing.T) {
		a := newApp(t, func(cfg *authkit.Config, _ *app) {
			cfg.SessionIdleTTL, cfg.SessionAbsoluteTTL = time.Hour, 3*time.Hour
		})
		b := a.browser()
		b.mustLogin("google")
		a.clock.Advance(61 * time.Minute)
		if signedIn(b) {
			t.Fatal("still signed in after the configured idle timeout")
		}
	})

	t.Run("revoked by deleting the row", func(t *testing.T) {
		a := newApp(t, nil)
		b := a.browser()
		b.mustLogin("google")
		if _, err := a.db.Exec(`DELETE FROM authkit_sessions`); err != nil {
			t.Fatal(err)
		}
		if signedIn(b) {
			t.Fatal("still signed in after the session row was deleted")
		}
	})

	t.Run("disabled user", func(t *testing.T) {
		a := newApp(t, nil)
		b := a.browser()
		b.mustLogin("google")
		u, err := a.store.UserByEmail(context.Background(), "ada@example.test")
		if err != nil {
			t.Fatal(err)
		}
		if err := a.store.SetDisabled(context.Background(), u.ID, true); err != nil {
			t.Fatal(err)
		}
		if signedIn(b) {
			t.Fatal("a disabled user is still signed in")
		}
		if code := b.loginError("google"); code != authkit.LoginErrDisabled {
			t.Errorf("disabled user signing in again: error = %q", code)
		}
	})

	t.Run("forged cookie", func(t *testing.T) {
		a := newApp(t, nil)
		b := a.browser()
		b.client.Jar.SetCookies(a.url(), []*http.Cookie{{Name: "__Host-session", Value: "made-up", Path: "/", Secure: true}})
		if signedIn(b) {
			t.Fatal("a made-up cookie signed in")
		}
	})

	t.Run("each sign-in gets a new session id", func(t *testing.T) {
		a := newApp(t, nil)
		b := a.browser()
		first := sessionCookie(t, callbackHop(t, b.login("google", "/app")))
		second := sessionCookie(t, callbackHop(t, b.login("google", "/app")))
		if first == second {
			t.Fatal("session id was reused across sign-ins")
		}
		if n := a.count("authkit_sessions"); n != 1 {
			t.Errorf("%d sessions; the browser's previous one should have been dropped", n)
		}
	})
}

func sessionCookie(t *testing.T, h hop) string {
	t.Helper()
	resp := http.Response{Header: h.Header}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-session" && c.Value != "" {
			return c.Value
		}
	}
	t.Fatal("no session cookie set")
	return ""
}

func TestCrossSiteRequestsRejected(t *testing.T) {
	a := newApp(t, nil)
	b := a.browser()
	b.mustLogin("google")

	cases := []struct {
		name    string
		method  string
		path    string
		headers []string
		want    int
	}{
		{"cross-site POST to the app", "POST", "/api/thing", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"same-site (sibling subdomain) POST", "POST", "/api/thing", []string{"Sec-Fetch-Site", "same-site"}, http.StatusForbidden},
		{"foreign Origin, old browser", "POST", "/api/thing", []string{"Origin", "https://evil.example"}, http.StatusForbidden},
		{"cross-site DELETE", "DELETE", "/api/thing", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"cross-site logout", "POST", "/auth/logout", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"same-origin POST", "POST", "/api/thing", []string{"Sec-Fetch-Site", "same-origin"}, http.StatusOK},
		{"matching Origin", "POST", "/api/thing", []string{"Origin", a.srv.URL}, http.StatusOK},
		{"cross-site GET is a normal link", "GET", "/api/thing", []string{"Sec-Fetch-Site", "cross-site"}, http.StatusOK},
		{"non-browser client", "POST", "/api/thing", nil, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := b.api(tc.method, tc.path, tc.headers...); got.Status != tc.want {
				t.Errorf("status = %d, want %d (%s)", got.Status, tc.want, got.Body)
			}
		})
	}
	// The rejected logout did not sign anyone out.
	if got := b.api("GET", "/auth/me"); got.Status != http.StatusOK {
		t.Errorf("session gone after a rejected cross-site logout: %d", got.Status)
	}
}

// accessApp is an app behind (fake) Cloudflare Access only.
func accessApp(t *testing.T, tweak func(cfg *authkit.Config, a *app)) *app {
	return newApp(t, func(cfg *authkit.Config, a *app) {
		cfg.Providers, cfg.BaseURL = nil, ""
		cfg.Access = &authkit.AccessConfig{TeamDomain: a.issuer.URL(), Audience: "access-aud-tag"}
		if tweak != nil {
			tweak(cfg, a)
		}
	})
}

func accessClaims(a *app) map[string]any {
	return map[string]any{
		"iss":   a.issuer.URL(),
		"aud":   []string{"access-aud-tag"},
		"sub":   "access-user-1",
		"email": "Ada@example.test",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
}

func TestCloudflareAccessAuthenticator(t *testing.T) {
	a := accessApp(t, nil)
	b := a.browser()
	call := func(token string) hop {
		if token == "" {
			return b.api("GET", "/api/thing")
		}
		return b.api("GET", "/api/thing", authkit.AccessHeader, token)
	}

	good := a.issuer.Sign(accessClaims(a))
	got := call(good)
	if got.Status != http.StatusOK || !strings.Contains(got.Body, "email=ada@example.test") {
		t.Fatalf("valid Access token = %d %q\nlogs:\n%s", got.Status, got.Body, a.logs)
	}
	// The same person on a later request is the same user, not a new one.
	_ = call(good)
	if n := a.count("authkit_users"); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}

	mutate := func(f func(c map[string]any)) string {
		c := accessClaims(a)
		f(c)
		return a.issuer.Sign(c)
	}
	rejections := map[string]string{
		"no header":      "",
		"not a JWT":      "garbage",
		"wrong audience": mutate(func(c map[string]any) { c["aud"] = []string{"another-application"} }),
		"wrong issuer":   mutate(func(c map[string]any) { c["iss"] = "https://other-team.cloudflareaccess.com" }),
		"expired":        mutate(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() }),
		"no email (service token)": mutate(func(c map[string]any) {
			delete(c, "email")
			c["common_name"] = "some-service-token"
		}),
		"signed by another key": authtest.SignWith(t, authtest.NewKey(t), "test-key", accessClaims(a)),
	}
	for name, token := range rejections {
		t.Run(name, func(t *testing.T) {
			if got := call(token); got.Status != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401 (%s)", got.Status, got.Body)
			}
		})
	}

	// With no login page of its own, a signed-out page load is a plain 401.
	if got := b.page("/app")[0]; got.Status != http.StatusUnauthorized {
		t.Errorf("signed-out page load behind Access = %d, want 401", got.Status)
	}
}

func TestAccessRespectsSignUpPolicyAndRoles(t *testing.T) {
	a := accessApp(t, func(cfg *authkit.Config, _ *app) {
		cfg.SignUp = authkit.SignUp{}
		cfg.SeedRoles = map[string][]string{"ada@example.test": {"admin"}}
	})
	b := a.browser()
	ada := a.issuer.Sign(accessClaims(a))
	if got := b.api("GET", "/api/admin", authkit.AccessHeader, ada); got.Status != http.StatusOK {
		t.Errorf("seeded admin through Access = %d %s", got.Status, got.Body)
	}
	c := accessClaims(a)
	c["sub"], c["email"] = "access-user-2", "stranger@example.test"
	if got := b.api("GET", "/api/thing", authkit.AccessHeader, a.issuer.Sign(c)); got.Status != http.StatusForbidden {
		t.Errorf("Access user outside a closed sign-up policy = %d, want 403", got.Status)
	}
}

// During a cutover both are accepted, and they resolve to the same user.
func TestAccessAndSessionTogether(t *testing.T) {
	a := newApp(t, func(cfg *authkit.Config, a *app) {
		cfg.Access = &authkit.AccessConfig{TeamDomain: a.issuer.URL(), Audience: "access-aud-tag"}
	})
	viaAccess := a.browser().api("GET", "/api/thing", authkit.AccessHeader, a.issuer.Sign(accessClaims(a)))
	b := a.browser()
	b.mustLogin("google")
	viaSession := b.api("GET", "/api/thing")
	if viaAccess.Status != http.StatusOK || viaAccess.Body != viaSession.Body {
		t.Errorf("Access gave %d %q, session gave %d %q", viaAccess.Status, viaAccess.Body, viaSession.Status, viaSession.Body)
	}
	if n := a.count("authkit_users"); n != 1 {
		t.Errorf("users = %d, want 1: Access and Google should link by email", n)
	}
}

func TestDevAuthenticator(t *testing.T) {
	a := newApp(t, func(cfg *authkit.Config, _ *app) {
		cfg.Providers, cfg.BaseURL = nil, ""
		cfg.SignUp = authkit.SignUp{} // closed: the dev user is admitted anyway
		cfg.DevUser = &authkit.DevUser{Email: "Dev@example.test", Name: "Dev", Roles: []string{"admin"}}
	})
	b := a.browser()
	for range 2 {
		if got := b.api("GET", "/api/admin"); got.Status != http.StatusOK || !strings.Contains(got.Body, "email=dev@example.test roles=admin") {
			t.Fatalf("dev user = %d %q", got.Status, got.Body)
		}
	}
	if n := a.count("authkit_users"); n != 1 {
		t.Errorf("users = %d, want 1", n)
	}
	if !strings.Contains(a.logs.String(), "development authenticator is on") {
		t.Error("no warning logged for the development authenticator")
	}
}

func TestNewRefusesUnsafeConfig(t *testing.T) {
	store, _ := newStore(t)
	google, _ := authkit.Google("id", "secret")
	dev := &authkit.DevUser{Email: "dev@example.test"}
	access := &authkit.AccessConfig{TeamDomain: "team.cloudflareaccess.com", Audience: "aud"}
	cases := []struct {
		name string
		cfg  authkit.Config
		want string // substring of the error; "" means accepted
	}{
		{"dev with providers", authkit.Config{Store: store, BaseURL: "https://a.example", Providers: []authkit.Provider{google}, DevUser: dev}, "DevUser cannot be combined"},
		{"dev with Access", authkit.Config{Store: store, Access: access, DevUser: dev}, "DevUser cannot be combined"},
		{"dev alone", authkit.Config{Store: store, DevUser: dev}, ""},
		{"nothing configured", authkit.Config{Store: store}, "nothing to authenticate with"},
		{"no store", authkit.Config{DevUser: dev}, "Store is required"},
		{"providers without BaseURL", authkit.Config{Store: store, Providers: []authkit.Provider{google}}, "BaseURL is required"},
		{"plain http on a real host", authkit.Config{Store: store, BaseURL: "http://app.example.com", Providers: []authkit.Provider{google}}, "must be https"},
		{"http on localhost", authkit.Config{Store: store, BaseURL: "http://localhost:8080", Providers: []authkit.Provider{google}}, ""},
		{"BaseURL with a path", authkit.Config{Store: store, BaseURL: "https://app.example.com/x", Providers: []authkit.Provider{google}}, "must be an origin"},
		{"duplicate provider", authkit.Config{Store: store, BaseURL: "https://a.example", Providers: []authkit.Provider{google, google}}, "duplicate provider"},
		{"off-site login path", authkit.Config{Store: store, DevUser: dev, LoginPath: "//evil.example"}, "local path"},
		{"empty allow-list", authkit.Config{Store: store, DevUser: dev, SignUp: authkit.SignUp{Mode: authkit.SignUpAllowList}}, "allow-list is empty"},
		{"Access without audience", authkit.Config{Store: store, Access: &authkit.AccessConfig{TeamDomain: "t.cloudflareaccess.com"}}, "TeamDomain and Audience"},
		{"Access alone", authkit.Config{Store: store, Access: access}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Logger = slog.New(slog.DiscardHandler)
			_, err := authkit.New(tc.cfg)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("error = %v, want one containing %q", err, tc.want)
			}
		})
	}
}

func TestInsecureCookiesOnLocalhostOnly(t *testing.T) {
	store, _ := newStore(t)
	gh := authtest.NewGitHub(t)
	p, _ := authkit.NewGitHub(authkit.GitHubConfig{ClientID: authtest.ClientID, ClientSecret: authtest.ClientSecret, WebURL: gh.Server.URL, APIURL: gh.Server.URL})
	k, err := authkit.New(authkit.Config{Store: store, BaseURL: "http://localhost:8080", Providers: []authkit.Provider{p}, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	k.Register(mux)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login/github", nil))
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "session-login" || cookies[0].Secure || !cookies[0].HttpOnly {
		t.Errorf("localhost login cookie = %+v", cookies)
	}
	if got := k.CallbackURL("github"); got != "http://localhost:8080/auth/callback/github" {
		t.Errorf("CallbackURL = %q", got)
	}
}

func TestSecretNeverPrints(t *testing.T) {
	const value = "s3cr3t-value"
	s := authkit.Secret(value)
	cfg := authkit.OIDCConfig{ClientID: "id", ClientSecret: s}

	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("config", "secret", s, "cfg", cfg)
	asJSON, err := json.Marshal(struct{ ClientSecret authkit.Secret }{s})
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{
		"%v":    fmt.Sprintf("%v", s),
		"print": fmt.Sprint(s),
		"%q":    fmt.Sprintf("%q", s),
		"%#v":   fmt.Sprintf("%#v", s),
		"%+v":   fmt.Sprintf("%+v", cfg),
		"%#v2":  fmt.Sprintf("%#v", cfg),
		"json":  string(asJSON),
		"slog":  logged.String(),
	}
	for how, out := range outputs {
		if strings.Contains(out, value) {
			t.Errorf("%s leaked the secret: %s", how, out)
		}
	}
	if s.Reveal() != value {
		t.Error("Reveal did not return the value")
	}
}

// Nothing the package logs during logins, good or bad, includes a secret.
func TestLogsHoldNoSecrets(t *testing.T) {
	a := newApp(t, nil)
	b := a.browser()
	hops := b.login("google", "/app")
	session := sessionCookie(t, callbackHop(t, hops))
	state := callbackHop(t, hops).URL.Query().Get("state")
	code := callbackHop(t, hops).URL.Query().Get("code")
	a.issuer.SetTamper(func(c map[string]any) { c["aud"] = "x" })
	_ = b.login("google", "/app")
	_ = b.login("github", "/app")
	logs := a.logs.String()
	if logs == "" {
		t.Fatal("nothing was logged")
	}
	for name, secret := range map[string]string{"client secret": authtest.ClientSecret, "session id": session, "state": state, "code": code} {
		if strings.Contains(logs, secret) {
			t.Errorf("logs contain the %s:\n%s", name, logs)
		}
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	session := []string{
		"AUTH_MODE", "session", "AUTH_BASE_URL", "https://app.example.com",
		"AUTH_GOOGLE_CLIENT_ID", "gid", "AUTH_GOOGLE_CLIENT_SECRET", "gsecret",
		"AUTH_GITHUB_CLIENT_ID", "hid", "AUTH_GITHUB_CLIENT_SECRET", "hsecret",
	}
	access := []string{"AUTH_ACCESS_TEAM_DOMAIN", "team.cloudflareaccess.com", "AUTH_ACCESS_AUD", "tag"}
	with := func(base []string, kv ...string) []string { return append(append([]string{}, base...), kv...) }

	t.Run("session", func(t *testing.T) {
		cfg, err := authkit.ConfigFromEnv(env(with(session,
			"AUTH_SIGNUP", "allowlist", "AUTH_SIGNUP_ALLOW", "ada@example.test, example.org",
			"AUTH_ADMIN_EMAILS", "ada@example.test,grace@example.test",
			"AUTH_SESSION_IDLE", "168h", "AUTH_SESSION_MAX", "720h",
			"AUTH_CLIENT_IP_HEADER", "CF-Connecting-IP")...))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Providers) != 2 || cfg.Providers[0].Name() != "google" || cfg.Providers[1].Name() != "github" {
			t.Errorf("providers = %v", cfg.Providers)
		}
		if cfg.Access != nil || cfg.DevUser != nil {
			t.Error("session mode enabled another authenticator")
		}
		if cfg.SignUp.Mode != authkit.SignUpAllowList || len(cfg.SignUp.Allow) != 2 || cfg.SignUp.Allow[1] != "example.org" {
			t.Errorf("sign-up = %+v", cfg.SignUp)
		}
		if len(cfg.SeedRoles) != 2 || cfg.SeedRoles["grace@example.test"][0] != "admin" {
			t.Errorf("seed roles = %v", cfg.SeedRoles)
		}
		if cfg.SessionIdleTTL != 168*time.Hour || cfg.SessionAbsoluteTTL != 720*time.Hour || cfg.ClientIPHeader != "CF-Connecting-IP" {
			t.Errorf("cfg = %+v", cfg)
		}
		store, _ := newStore(t)
		cfg.Store = store
		if _, err := authkit.New(cfg); err != nil {
			t.Errorf("New rejected the env config: %v", err)
		}
	})
	t.Run("access ignores provider credentials", func(t *testing.T) {
		cfg, err := authkit.ConfigFromEnv(env(with(with(session, access...), "AUTH_MODE", "access")...))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Providers) != 0 || cfg.Access == nil || cfg.Access.Audience != "tag" {
			t.Errorf("cfg = %+v", cfg)
		}
		if cfg.SignUp.Mode != authkit.SignUpClosed {
			t.Error("sign-up should default to closed")
		}
	})
	t.Run("both during cutover", func(t *testing.T) {
		cfg, err := authkit.ConfigFromEnv(env(with(with(session, access...), "AUTH_MODE", "access, session")...))
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Providers) != 2 || cfg.Access == nil {
			t.Errorf("cfg = %+v", cfg)
		}
	})
	t.Run("dev", func(t *testing.T) {
		cfg, err := authkit.ConfigFromEnv(env("AUTH_MODE", "dev", "AUTH_DEV_USER", "dev@example.test", "AUTH_DEV_ROLES", "admin,editor"))
		if err != nil {
			t.Fatal(err)
		}
		if cfg.DevUser == nil || cfg.DevUser.Email != "dev@example.test" || len(cfg.DevUser.Roles) != 2 {
			t.Errorf("dev user = %+v", cfg.DevUser)
		}
	})

	bad := map[string][]string{
		"no mode":                    nil,
		"unknown mode":               {"AUTH_MODE", "magic"},
		"dev combined":               {"AUTH_MODE", "dev,session", "AUTH_DEV_USER", "dev@example.test"},
		"dev user left set":          with(session, "AUTH_DEV_USER", "dev@example.test"),
		"dev without user":           {"AUTH_MODE", "dev"},
		"session without providers":  {"AUTH_MODE", "session", "AUTH_BASE_URL", "https://app.example.com"},
		"session without base URL":   {"AUTH_MODE", "session", "AUTH_GITHUB_CLIENT_ID", "id", "AUTH_GITHUB_CLIENT_SECRET", "s"},
		"provider id without secret": {"AUTH_MODE", "session", "AUTH_BASE_URL", "https://app.example.com", "AUTH_GOOGLE_CLIENT_ID", "gid"},
		"access without settings":    {"AUTH_MODE", "access"},
		"unknown sign-up":            with(session, "AUTH_SIGNUP", "maybe"),
		"bad duration":               with(session, "AUTH_SESSION_IDLE", "a month"),
		"negative duration":          with(session, "AUTH_SESSION_MAX", "-1h"),
	}
	for name, kv := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := authkit.ConfigFromEnv(env(kv...)); err == nil {
				t.Error("no error")
			} else if strings.Contains(err.Error(), "gsecret") || strings.Contains(err.Error(), "hsecret") {
				t.Errorf("error leaks a secret: %v", err)
			}
		})
	}
}
