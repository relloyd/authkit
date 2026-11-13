// Package authtest holds the fakes the tests log in against: an OpenID
// Connect issuer (which doubles as a Cloudflare Access certs endpoint) and a
// GitHub. Both run as httptest servers and behave like the real thing where
// it matters: the issuer signs real RS256 tokens and both enforce PKCE.
package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Client credentials every fake accepts.
const (
	ClientID     = "test-client-id"
	ClientSecret = "test-client-secret-value"
)

var (
	keyOnce sync.Once
	testKey *rsa.PrivateKey
)

// key returns one RSA key shared by the whole test binary; generating one
// per test is slow under the race detector.
func key(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

// NewKey returns a fresh key, for signing tokens the issuer did not issue.
func NewKey(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// SignWith signs claims as a compact RS256 JWT with the given key.
func SignWith(t testing.TB, k *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: k, KeyID: kid}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type pendingCode struct {
	challenge string
	nonce     string
	redirect  string
}

// codes is the authorisation-code table both fakes share.
type codes struct {
	mu sync.Mutex
	m  map[string]pendingCode
	n  int
}

// authorize plays the provider's sign-in page: it approves at once and
// redirects back with a code, as if the user had clicked through.
func (c *codes) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != ClientID || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "bad authorisation request", http.StatusBadRequest)
		return
	}
	c.mu.Lock()
	c.n++
	code := "code-" + strconv.Itoa(c.n)
	if c.m == nil {
		c.m = map[string]pendingCode{}
	}
	c.m[code] = pendingCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	c.mu.Unlock()
	back := q.Get("redirect_uri") + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(q.Get("state"))
	http.Redirect(w, r, back, http.StatusFound)
}

// redeem checks a token request the way a real provider does: client
// secret, single-use code, matching redirect URI and the PKCE verifier.
func (c *codes) redeem(r *http.Request) (pendingCode, bool) {
	if err := r.ParseForm(); err != nil {
		return pendingCode{}, false
	}
	id, secret, basic := r.BasicAuth()
	if !basic {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != ClientID || secret != ClientSecret {
		return pendingCode{}, false
	}
	c.mu.Lock()
	pc, ok := c.m[r.PostForm.Get("code")]
	delete(c.m, r.PostForm.Get("code"))
	c.mu.Unlock()
	if !ok || pc.redirect != r.PostForm.Get("redirect_uri") {
		return pendingCode{}, false
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != pc.challenge {
		return pendingCode{}, false
	}
	return pc, true
}

// Issuer is a fake OpenID Connect issuer.
type Issuer struct {
	Server *httptest.Server
	t      testing.TB
	codes  codes

	mu sync.Mutex
	// The account that "signs in" next.
	Subject       string
	Email         string
	Name          string
	EmailVerified bool
	// Tamper, when set, edits the ID token claims before signing.
	Tamper func(claims map[string]any)
	// SigningKey, when set, signs ID tokens instead of the published key.
	SigningKey *rsa.PrivateKey
}

// NewIssuer starts a fake issuer signing in ada@example.test.
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	is := &Issuer{t: t, Subject: "sub-ada", Email: "ada@example.test", Name: "Ada", EmailVerified: true}
	mux := http.NewServeMux()
	is.Server = httptest.NewServer(mux)
	t.Cleanup(is.Server.Close)
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                is.URL(),
			"authorization_endpoint":                is.URL() + "/authorize",
			"token_endpoint":                        is.URL() + "/token",
			"jwks_uri":                              is.URL() + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	jwks := func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key(t).PublicKey, KeyID: "test-key", Algorithm: "RS256", Use: "sig"},
		}})
	}
	mux.HandleFunc("GET /jwks", jwks)
	mux.HandleFunc("GET /cdn-cgi/access/certs", jwks) // Cloudflare Access's path
	mux.HandleFunc("GET /authorize", is.codes.authorize)
	mux.HandleFunc("POST /token", is.token)
	return is
}

// URL is the issuer URL.
func (is *Issuer) URL() string { return is.Server.URL }

// SetUser changes who signs in next.
func (is *Issuer) SetUser(subject, email string, verified bool) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Subject, is.Email, is.EmailVerified = subject, email, verified
}

// SetTamper installs a function that edits the next ID tokens' claims.
func (is *Issuer) SetTamper(f func(claims map[string]any)) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.Tamper = f
}

// SetSigningKey makes the issuer sign with a key it does not publish.
func (is *Issuer) SetSigningKey(k *rsa.PrivateKey) {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.SigningKey = k
}

// Sign signs claims with the issuer's published key.
func (is *Issuer) Sign(claims map[string]any) string {
	return SignWith(is.t, key(is.t), "test-key", claims)
}

func (is *Issuer) token(w http.ResponseWriter, r *http.Request) {
	pc, ok := is.codes.redeem(r)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		writeJSON(w, map[string]string{"error": "invalid_grant"})
		return
	}
	is.mu.Lock()
	now := time.Now()
	claims := map[string]any{
		"iss":            is.URL(),
		"aud":            ClientID,
		"sub":            is.Subject,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"nonce":          pc.nonce,
		"email":          is.Email,
		"email_verified": is.EmailVerified,
		"name":           is.Name,
	}
	if is.Tamper != nil {
		is.Tamper(claims)
	}
	signing := is.SigningKey
	is.mu.Unlock()
	if signing == nil {
		signing = key(is.t)
	}
	writeJSON(w, map[string]any{
		"access_token": "fake-access-token",
		"token_type":   "Bearer",
		"expires_in":   300,
		"id_token":     SignWith(is.t, signing, "test-key", claims),
	})
}

// GitHubEmail is one row of GitHub's /user/emails answer.
type GitHubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// GitHub is a fake github.com and api.github.com on one server.
type GitHub struct {
	Server *httptest.Server
	codes  codes

	mu     sync.Mutex
	ID     int64
	Login  string
	Name   string
	Emails []GitHubEmail
}

// NewGitHub starts a fake GitHub signing in ada@example.test (account 4242).
func NewGitHub(t testing.TB) *GitHub {
	t.Helper()
	gh := &GitHub{ID: 4242, Login: "ada", Name: "Ada L", Emails: []GitHubEmail{
		{Email: "old@example.test", Verified: true},
		{Email: "ada@example.test", Primary: true, Verified: true},
	}}
	const token = "fake-github-token"
	mux := http.NewServeMux()
	gh.Server = httptest.NewServer(mux)
	t.Cleanup(gh.Server.Close)
	mux.HandleFunc("GET /login/oauth/authorize", gh.codes.authorize)
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := gh.codes.redeem(r); !ok {
			// GitHub answers 200 with an error body.
			writeJSON(w, map[string]string{"error": "bad_verification_code"})
			return
		}
		writeJSON(w, map[string]string{"access_token": token, "token_type": "bearer", "scope": "read:user,user:email"})
	})
	authed := func(h func(w http.ResponseWriter)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "bad credentials", http.StatusUnauthorized)
				return
			}
			gh.mu.Lock()
			defer gh.mu.Unlock()
			h(w)
		}
	}
	mux.HandleFunc("GET /user", authed(func(w http.ResponseWriter) {
		writeJSON(w, map[string]any{"id": gh.ID, "login": gh.Login, "name": gh.Name})
	}))
	mux.HandleFunc("GET /user/emails", authed(func(w http.ResponseWriter) {
		writeJSON(w, gh.Emails)
	}))
	return gh
}

// SetUser changes who signs in next.
func (gh *GitHub) SetUser(id int64, emails ...GitHubEmail) {
	gh.mu.Lock()
	defer gh.mu.Unlock()
	gh.ID, gh.Emails = id, emails
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
