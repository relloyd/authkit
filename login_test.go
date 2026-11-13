package authkit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/relloyd/authkit"
	"github.com/relloyd/authkit/internal/authtest"
)

func TestOIDCLoginRoundTrip(t *testing.T) {
	a := newApp(t, nil)
	b := a.browser()

	// Signed out: a page load goes to the login page, remembering the page.
	hops := b.page("/app/deep?x=1")
	if got := hops[0].Header.Get("Location"); got != "/login?return=%2Fapp%2Fdeep%3Fx%3D1" {
		t.Fatalf("signed-out page load redirected to %q", got)
	}

	// The whole flow: login -> issuer -> callback -> the remembered page.
	hops = b.login("google", "/app/deep?x=1")
	end := last(hops)
	if end.URL.RequestURI() != "/app/deep?x=1" || end.Status != http.StatusOK {
		t.Fatalf("login ended at %s with %d, want /app/deep?x=1 200\nlogs:\n%s", end.URL, end.Status, a.logs)
	}
	if !strings.Contains(end.Body, "email=ada@example.test") {
		t.Fatalf("protected page body = %q", end.Body)
	}

	// The authorisation request carried state, a nonce and an S256 challenge.
	authz, _ := url.Parse(hops[0].Header.Get("Location"))
	q := authz.Query()
	for _, param := range []string{"state", "nonce", "code_challenge"} {
		if q.Get(param) == "" {
			t.Errorf("authorisation URL has no %s", param)
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if want := a.srv.URL + "/auth/callback/google"; q.Get("redirect_uri") != want {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), want)
	}

	// The session cookie: __Host- prefix, HttpOnly, Secure, SameSite=Lax.
	var session *http.Cookie
	resp := http.Response{Header: callbackHop(t, hops).Header}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-session" && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("callback set no __Host-session cookie")
	}
	if !session.HttpOnly || !session.Secure || session.SameSite != http.SameSiteLaxMode || session.Path != "/" || session.Domain != "" {
		t.Errorf("session cookie attributes wrong: %+v", session)
	}
	// Only a hash of it is stored.
	var stored string
	if err := a.db.QueryRow(`SELECT id_hash FROM authkit_sessions`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == session.Value || len(stored) != 64 {
		t.Errorf("stored session id %q is not a SHA-256 of the cookie", stored)
	}
	if n := a.count("authkit_pending_logins"); n != 0 {
		t.Errorf("%d pending logins left after a completed login", n)
	}

	// /auth/me for a front end.
	me := b.api("GET", "/auth/me")
	var got struct {
		Email string   `json:"email"`
		Name  string   `json:"name"`
		Roles []string `json:"roles"`
		ID    int64    `json:"id"`
	}
	if err := json.Unmarshal([]byte(me.Body), &got); err != nil {
		t.Fatalf("/auth/me body %q: %v", me.Body, err)
	}
	if me.Status != http.StatusOK || got.Email != "ada@example.test" || got.Name != "Ada" || got.ID == 0 || got.Roles == nil {
		t.Errorf("/auth/me = %d %s", me.Status, me.Body)
	}

	// Logout deletes the session server-side.
	if out := b.api("POST", "/auth/logout", "Sec-Fetch-Site", "same-origin"); out.Status != http.StatusNoContent {
		t.Fatalf("logout = %d", out.Status)
	}
	if n := a.count("authkit_sessions"); n != 0 {
		t.Errorf("%d sessions left after logout", n)
	}
	if me := b.api("GET", "/auth/me"); me.Status != http.StatusUnauthorized {
		t.Errorf("/auth/me after logout = %d, want 401", me.Status)
	}
}

func TestGitHubLoginRoundTrip(t *testing.T) {
	a := newApp(t, nil)
	b := a.browser()
	hops := b.login("github", "/app")
	end := last(hops)
	if end.URL.Path != "/app" || !strings.Contains(end.Body, "email=ada@example.test") {
		t.Fatalf("login ended at %s with %d %q\nlogs:\n%s", end.URL, end.Status, end.Body, a.logs)
	}
	authz, _ := url.Parse(hops[0].Header.Get("Location"))
	if authz.Query().Get("code_challenge_method") != "S256" {
		t.Error("GitHub authorisation URL has no PKCE challenge")
	}
	// The identity is keyed by GitHub's numeric account id, not the email.
	var subject string
	if err := a.db.QueryRow(`SELECT subject FROM authkit_identities WHERE provider = 'github'`).Scan(&subject); err != nil {
		t.Fatal(err)
	}
	if subject != "4242" {
		t.Errorf("github identity subject = %q, want 4242", subject)
	}
}

func TestGitHubNeedsPrimaryVerifiedEmail(t *testing.T) {
	cases := map[string][]authtest.GitHubEmail{
		"no emails":            nil,
		"primary not verified": {{Email: "ada@example.test", Primary: true}},
		"verified not primary": {{Email: "ada@example.test", Verified: true}},
	}
	for name, emails := range cases {
		t.Run(name, func(t *testing.T) {
			a := newApp(t, nil)
			a.github.SetUser(4242, emails...)
			if code := a.browser().loginError("github"); code != authkit.LoginErrEmailUnverified {
				t.Errorf("error = %q, want %q", code, authkit.LoginErrEmailUnverified)
			}
			if n := a.count("authkit_users"); n != 0 {
				t.Errorf("%d users created", n)
			}
		})
	}
}

func TestIDTokenRejections(t *testing.T) {
	cases := []struct {
		name  string
		setup func(is *authtest.Issuer, t *testing.T)
		want  string
		log   string // what the log must say, proving it failed for this reason
	}{
		{"wrong audience", func(is *authtest.Issuer, _ *testing.T) {
			is.SetTamper(func(c map[string]any) { c["aud"] = "some-other-client" })
		}, authkit.LoginErrProvider, "expected audience"},
		{"wrong nonce", func(is *authtest.Issuer, _ *testing.T) {
			is.SetTamper(func(c map[string]any) { c["nonce"] = "not-the-nonce" })
		}, authkit.LoginErrProvider, "nonce does not match"},
		{"missing nonce", func(is *authtest.Issuer, _ *testing.T) {
			is.SetTamper(func(c map[string]any) { delete(c, "nonce") })
		}, authkit.LoginErrProvider, "nonce does not match"},
		{"wrong issuer", func(is *authtest.Issuer, _ *testing.T) {
			is.SetTamper(func(c map[string]any) { c["iss"] = "https://evil.example" })
		}, authkit.LoginErrProvider, "issued by a different provider"},
		{"expired token", func(is *authtest.Issuer, _ *testing.T) {
			is.SetTamper(func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() })
		}, authkit.LoginErrProvider, "token is expired"},
		{"signed by another key", func(is *authtest.Issuer, t *testing.T) {
			is.SetSigningKey(authtest.NewKey(t))
		}, authkit.LoginErrProvider, "failed to verify signature"},
		{"unverified email", func(is *authtest.Issuer, _ *testing.T) {
			is.SetUser("sub-ada", "ada@example.test", false)
		}, authkit.LoginErrEmailUnverified, "no verified email"},
		{"no email", func(is *authtest.Issuer, _ *testing.T) {
			is.SetTamper(func(c map[string]any) { delete(c, "email") })
		}, authkit.LoginErrEmailUnverified, "no verified email"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newApp(t, nil)
			tc.setup(a.issuer, t)
			if code := a.browser().loginError("google"); code != tc.want {
				t.Errorf("error = %q, want %q\nlogs:\n%s", code, tc.want, a.logs)
			}
			if !strings.Contains(a.logs.String(), tc.log) {
				t.Errorf("log does not mention %q:\n%s", tc.log, a.logs)
			}
			if n := a.count("authkit_users") + a.count("authkit_sessions"); n != 0 {
				t.Errorf("a rejected login created %d rows", n)
			}
		})
	}
}

func TestEmailVerifiedAsString(t *testing.T) {
	a := newApp(t, nil)
	a.issuer.SetTamper(func(c map[string]any) { c["email_verified"] = "true" })
	a.browser().mustLogin("google")
}

func TestCallbackStateRejections(t *testing.T) {
	a := newApp(t, nil)

	// startLogin runs the flow up to the provider's redirect back, without
	// delivering the callback, and returns the callback URL.
	startLogin := func(t *testing.T, b *browser) *url.URL {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/auth/login/google", nil)
		resp, err := b.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		resp2, err := b.client.Get(resp.Header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		_ = resp2.Body.Close()
		cb, err := url.Parse(resp2.Header.Get("Location"))
		if err != nil || !strings.HasPrefix(cb.Path, "/auth/callback/") {
			t.Fatalf("provider redirected to %q", resp2.Header.Get("Location"))
		}
		return cb
	}
	deliver := func(t *testing.T, b *browser, cb *url.URL) string {
		t.Helper()
		end := last(b.page(cb.RequestURI()))
		if end.URL.Path != "/login" {
			t.Fatalf("callback was accepted: ended at %s", end.URL)
		}
		if me := b.api("GET", "/auth/me"); me.Status != http.StatusUnauthorized {
			t.Fatalf("rejected callback left a session")
		}
		return end.URL.Query().Get("error")
	}
	edit := func(cb *url.URL, key, value string) *url.URL {
		q := cb.Query()
		q.Set(key, value)
		out := *cb
		out.RawQuery = q.Encode()
		return &out
	}

	t.Run("state altered", func(t *testing.T) {
		b := a.browser()
		cb := startLogin(t, b)
		if code := deliver(t, b, edit(cb, "state", "forged")); code != authkit.LoginErrInvalidState {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("state missing", func(t *testing.T) {
		b := a.browser()
		cb := startLogin(t, b)
		q := cb.Query()
		q.Del("state")
		cb.RawQuery = q.Encode()
		if code := deliver(t, b, cb); code != authkit.LoginErrInvalidState {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("callback delivered to another browser (login CSRF)", func(t *testing.T) {
		attacker, victim := a.browser(), a.browser()
		cb := startLogin(t, attacker)
		if code := deliver(t, victim, cb); code != authkit.LoginErrInvalidState {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("callback replayed", func(t *testing.T) {
		b := a.browser()
		hops := b.login("google", "/app")
		cb := callbackHop(t, hops).URL
		_ = b.api("POST", "/auth/logout")
		// Put the state cookie back, as an attacker holding the URL and the
		// cookie would; the server-side record is single-use.
		b.client.Jar.SetCookies(a.url(), []*http.Cookie{{Name: "__Host-session-login", Value: cb.Query().Get("state"), Path: "/", Secure: true}})
		if code := deliver(t, b, cb); code != authkit.LoginErrInvalidState {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("pending login expired", func(t *testing.T) {
		b := a.browser()
		cb := startLogin(t, b)
		a.clock.Advance(11 * time.Minute)
		// The cookie jar runs on the real clock, so the state cookie is still sent.
		if code := deliver(t, b, cb); code != authkit.LoginErrInvalidState {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("callback for a different provider", func(t *testing.T) {
		b := a.browser()
		cb := startLogin(t, b)
		cb.Path = "/auth/callback/github"
		if code := deliver(t, b, cb); code != authkit.LoginErrInvalidState {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("code altered", func(t *testing.T) {
		b := a.browser()
		cb := startLogin(t, b)
		if code := deliver(t, b, edit(cb, "code", "stolen-code")); code != authkit.LoginErrProvider {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("user cancelled at the provider", func(t *testing.T) {
		b := a.browser()
		cb := startLogin(t, b)
		q := cb.Query()
		q.Del("code")
		q.Set("error", "access_denied")
		cb.RawQuery = q.Encode()
		if code := deliver(t, b, cb); code != authkit.LoginErrDenied {
			t.Errorf("error = %q", code)
		}
	})
	t.Run("unknown provider", func(t *testing.T) {
		b := a.browser()
		if got := last(b.page("/auth/login/facebook")); got.Status != http.StatusNotFound {
			t.Errorf("status = %d, want 404", got.Status)
		}
	})
}

func TestReturnPathCannotLeaveTheSite(t *testing.T) {
	a := newApp(t, nil)
	for _, bad := range []string{
		"https://evil.example/",
		"//evil.example/",
		`/\evil.example`,
		`\\evil.example`,
		"http:evil.example",
		"javascript:alert(1)",
		"/ok\r\nSet-Cookie: x=1",
		"evil.example",
	} {
		hops := a.browser().login("google", bad)
		if got := callbackHop(t, hops).Header.Get("Location"); got != "/" {
			t.Errorf("return=%q: callback redirected to %q, want /", bad, got)
		}
	}
	// A local path with a query survives.
	hops := a.browser().login("google", "/app/x?y=1#z")
	if got := callbackHop(t, hops).Header.Get("Location"); got != "/app/x?y=1#z" {
		t.Errorf("local return path became %q", got)
	}
}

func TestAccountLinking(t *testing.T) {
	a := newApp(t, nil)
	b := a.browser()

	// Same verified address through Google then GitHub: one user, two identities.
	b.mustLogin("google")
	b.mustLogin("github")
	if users, ids := a.count("authkit_users"), a.count("authkit_identities"); users != 1 || ids != 2 {
		t.Fatalf("users = %d, identities = %d; want 1 and 2", users, ids)
	}

	// The address differs only by case and spacing: still the same user.
	a.issuer.SetUser("sub-ada-2", "  Ada@Example.TEST ", true)
	b.mustLogin("google")
	if users := a.count("authkit_users"); users != 1 {
		t.Fatalf("users = %d after a case-variant address; want 1", users)
	}

	// A different address is a different user.
	a.github.SetUser(777, authtest.GitHubEmail{Email: "grace@example.test", Primary: true, Verified: true})
	b.mustLogin("github")
	if users := a.count("authkit_users"); users != 2 {
		t.Fatalf("users = %d; want 2", users)
	}

	// Identities are keyed by provider and subject: when a known account's
	// address changes at the provider, it is still the same user here, and
	// it does not take over whoever owns the new address.
	a.issuer.SetUser("sub-ada", "grace@example.test", true)
	hops := b.login("google", "/app")
	if body := last(hops).Body; !strings.Contains(body, "email=ada@example.test") {
		t.Fatalf("known subject with a changed address signed in as %q", body)
	}

	// An unverified address never links, even to an existing account.
	a.issuer.SetUser("sub-mallory", "grace@example.test", false)
	if code := a.browser().loginError("google"); code != authkit.LoginErrEmailUnverified {
		t.Errorf("unverified address: error = %q", code)
	}
}

func TestSignUpPolicy(t *testing.T) {
	cases := []struct {
		name   string
		signUp authkit.SignUp
		seed   map[string][]string
		email  string
		want   string // "" means admitted
	}{
		{"open admits anyone", authkit.SignUp{Mode: authkit.SignUpOpen}, nil, "ada@example.test", ""},
		{"closed admits nobody", authkit.SignUp{}, nil, "ada@example.test", authkit.LoginErrSignUpClosed},
		{"closed admits a seeded address", authkit.SignUp{}, map[string][]string{"Ada@Example.test": {"admin"}}, "ada@example.test", ""},
		{"allow-list address", authkit.SignUp{Mode: authkit.SignUpAllowList, Allow: []string{"ADA@example.test"}}, nil, "ada@example.test", ""},
		{"allow-list domain", authkit.SignUp{Mode: authkit.SignUpAllowList, Allow: []string{"@example.test"}}, nil, "ada@example.test", ""},
		{"allow-list bare domain", authkit.SignUp{Mode: authkit.SignUpAllowList, Allow: []string{"example.test"}}, nil, "ada@example.test", ""},
		{"allow-list miss", authkit.SignUp{Mode: authkit.SignUpAllowList, Allow: []string{"grace@example.test", "other.test"}}, nil, "ada@example.test", authkit.LoginErrSignUpClosed},
		{"allow-list does not match subdomains", authkit.SignUp{Mode: authkit.SignUpAllowList, Allow: []string{"example.test"}}, nil, "ada@sub.example.test", authkit.LoginErrSignUpClosed},
		{"allow-list does not match a suffix", authkit.SignUp{Mode: authkit.SignUpAllowList, Allow: []string{"example.test"}}, nil, "ada@evilexample.test", authkit.LoginErrSignUpClosed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newApp(t, func(cfg *authkit.Config, _ *app) {
				cfg.SignUp, cfg.SeedRoles = tc.signUp, tc.seed
			})
			a.issuer.SetUser("sub-1", tc.email, true)
			b := a.browser()
			if tc.want == "" {
				b.mustLogin("google")
				return
			}
			if code := b.loginError("google"); code != tc.want {
				t.Errorf("error = %q, want %q", code, tc.want)
			}
			if n := a.count("authkit_users"); n != 0 {
				t.Errorf("%d users created", n)
			}
		})
	}

	t.Run("closed still admits existing users", func(t *testing.T) {
		a := newApp(t, func(cfg *authkit.Config, _ *app) { cfg.SignUp = authkit.SignUp{} })
		if _, err := a.store.CreateUser(context.Background(), "ada@example.test", "Ada", nil); err != nil {
			t.Fatal(err)
		}
		a.browser().mustLogin("google")
	})
}

func TestRoles(t *testing.T) {
	a := newApp(t, func(cfg *authkit.Config, _ *app) {
		cfg.SeedRoles = map[string][]string{"ada@example.test": {"admin"}}
	})

	// Signed out.
	anon := a.browser()
	if got := anon.api("GET", "/api/admin"); got.Status != http.StatusUnauthorized || !strings.Contains(got.Body, "unauthenticated") {
		t.Errorf("signed-out API call = %d %q, want 401 JSON", got.Status, got.Body)
	}
	if got := anon.page("/admin")[0]; got.Status != http.StatusSeeOther || got.Header.Get("Location") != "/login?return=%2Fadmin" {
		t.Errorf("signed-out admin page = %d to %q", got.Status, got.Header.Get("Location"))
	}

	// Ada is seeded as admin.
	admin := a.browser()
	admin.mustLogin("google")
	if got := last(admin.page("/admin")); got.Status != http.StatusOK || !strings.Contains(got.Body, "roles=admin") {
		t.Errorf("admin page for an admin = %d %q", got.Status, got.Body)
	}
	if got := admin.api("GET", "/api/admin"); got.Status != http.StatusOK {
		t.Errorf("admin API for an admin = %d", got.Status)
	}

	// Grace is a plain user.
	a.issuer.SetUser("sub-grace", "grace@example.test", true)
	plain := a.browser()
	plain.mustLogin("google")
	if got := last(plain.page("/admin")); got.Status != http.StatusForbidden {
		t.Errorf("admin page for a plain user = %d, want 403", got.Status)
	}
	if got := plain.api("GET", "/api/admin"); got.Status != http.StatusForbidden || !strings.Contains(got.Body, "forbidden") {
		t.Errorf("admin API for a plain user = %d %q, want 403 JSON", got.Status, got.Body)
	}

	// A role granted by the app takes effect on the next request.
	var graceID int64
	if err := a.db.QueryRow(`SELECT id FROM authkit_users WHERE email = 'grace@example.test'`).Scan(&graceID); err != nil {
		t.Fatal(err)
	}
	if err := a.store.AddRoles(context.Background(), graceID, []string{"admin", "editor"}); err != nil {
		t.Fatal(err)
	}
	if got := plain.api("GET", "/api/admin"); got.Status != http.StatusOK || !strings.Contains(got.Body, "roles=admin,editor") {
		t.Errorf("after granting admin = %d %q", got.Status, got.Body)
	}
	if err := a.store.SetRoles(context.Background(), graceID, nil); err != nil {
		t.Fatal(err)
	}
	if got := plain.api("GET", "/api/admin"); got.Status != http.StatusForbidden {
		t.Errorf("after revoking admin = %d, want 403", got.Status)
	}
}

func TestRequireUserAnswersByKindOfRequest(t *testing.T) {
	a := newApp(t, nil)
	b := a.browser()

	// API prefix: always 401 JSON, even for a navigation.
	req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/api/thing", nil)
	req.Header.Set("Accept", "text/html")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	if got := b.do(req)[0]; got.Status != http.StatusUnauthorized || got.Header.Get("Content-Type") != "application/json" {
		t.Errorf("API path = %d %s", got.Status, got.Header.Get("Content-Type"))
	}
	// fetch() to a page path: 401, not a redirect a script cannot use.
	if got := b.api("GET", "/app", "Sec-Fetch-Mode", "cors"); got.Status != http.StatusUnauthorized {
		t.Errorf("fetch to a page path = %d, want 401", got.Status)
	}
	// A navigation: redirect to login.
	if got := b.page("/app")[0]; got.Status != http.StatusSeeOther {
		t.Errorf("navigation = %d, want 303", got.Status)
	}
	// LoadUser pages work signed out.
	if got := last(b.page("/")); got.Status != http.StatusOK || got.Body != "nobody" {
		t.Errorf("public page = %d %q", got.Status, got.Body)
	}
}

func TestProvidersEndpoint(t *testing.T) {
	a := newApp(t, nil)
	got := a.browser().api("GET", "/auth/providers")
	want := `{"providers":[{"name":"google","label":"Google","login_url":"/auth/login/google"},{"name":"github","label":"GitHub","login_url":"/auth/login/github"}]}`
	if strings.TrimSpace(got.Body) != want {
		t.Errorf("providers = %s", got.Body)
	}
}

func TestRateLimit(t *testing.T) {
	a := newApp(t, func(cfg *authkit.Config, _ *app) {
		cfg.RatePerMinute, cfg.RateBurst = 6, 3
		cfg.ClientIPHeader = "CF-Connecting-IP"
	})
	b := a.browser()
	hit := func(ip string) hop {
		return b.api("GET", "/auth/login/nope", "CF-Connecting-IP", ip)
	}
	for i := range 3 {
		if got := hit("203.0.113.1"); got.Status != http.StatusNotFound {
			t.Fatalf("request %d = %d, want through to the handler (404)", i+1, got.Status)
		}
	}
	limited := hit("203.0.113.1")
	if limited.Status != http.StatusTooManyRequests || limited.Header.Get("Retry-After") != "10" {
		t.Fatalf("4th request = %d Retry-After %q, want 429 and 10", limited.Status, limited.Header.Get("Retry-After"))
	}
	// Another client is unaffected.
	if got := hit("203.0.113.2"); got.Status != http.StatusNotFound {
		t.Errorf("other client = %d", got.Status)
	}
	// Tokens come back with time: 6 a minute is one every 10 seconds.
	a.clock.Advance(10 * time.Second)
	if got := hit("203.0.113.1"); got.Status != http.StatusNotFound {
		t.Errorf("after waiting = %d", got.Status)
	}
	if got := hit("203.0.113.1"); got.Status != http.StatusTooManyRequests {
		t.Errorf("second after waiting = %d, want 429", got.Status)
	}
	// /auth/me is not rate limited.
	for range 10 {
		if got := b.api("GET", "/auth/me", "CF-Connecting-IP", "203.0.113.1"); got.Status != http.StatusUnauthorized {
			t.Fatalf("/auth/me = %d", got.Status)
		}
	}
}
