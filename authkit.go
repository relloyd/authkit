// Package authkit gives a stdlib net/http app its own login: Google and
// GitHub sign-in, server-side sessions, sign-up policy and per-app roles.
//
// It is a library embedded in each app, not a service. Each app keeps its
// users and sessions in its own database through the Store interface.
//
// One question, "who is this request?", is answered by an Authenticator.
// Three are built in and chosen by configuration: the package's own session
// cookie, a Cloudflare Access token, and a fixed user for local development.
// Handlers only ever see a *User in the request context, so an app can start
// behind Cloudflare Access and move to its own login without changing them.
//
// See the README for integration, configuration and the threat model.
package authkit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Defaults applied by New when a Config field is zero.
const (
	DefaultPrefix             = "/auth"
	DefaultLoginPath          = "/login"
	DefaultCookieName         = "session"
	DefaultSessionIdleTTL     = 30 * 24 * time.Hour
	DefaultSessionAbsoluteTTL = 90 * 24 * time.Hour
	DefaultRatePerMinute      = 30
	DefaultRateBurst          = 10

	pendingLoginTTL = 10 * time.Minute
	touchInterval   = time.Minute
	sweepInterval   = 15 * time.Minute
)

// Config configures a Kit. Store is always required; the rest depends on
// which authenticators are wanted:
//
//   - own login (session cookie): BaseURL and at least one Provider;
//   - Cloudflare Access: Access;
//   - local development: DevUser, and neither of the above.
//
// Providers and Access may both be set, which accepts either during a
// cutover from Access to own login.
type Config struct {
	// Store holds users, identities, sessions and pending logins.
	Store Store

	// BaseURL is the app's public origin, e.g. "https://derp.example.com".
	// Callback URLs are BaseURL + Prefix + "/callback/" + provider name.
	// It must be https, except for localhost during development.
	BaseURL string
	// Prefix is where Register mounts the login handlers. Default "/auth".
	Prefix string
	// LoginPath is the app's own login page. RequireUser sends signed-out
	// page loads there with ?return=<path>, and a failed login lands there
	// with ?error=<code>. Default "/login".
	LoginPath string
	// APIPrefixes are path prefixes that always get a 401 JSON answer, never
	// a redirect to the login page. Default ["/api/"].
	APIPrefixes []string

	// Providers are the sign-in methods offered, e.g. Google and GitHub.
	Providers []Provider
	// Access enables the Cloudflare Access authenticator.
	Access *AccessConfig
	// DevUser enables the development authenticator: every request is this
	// user. New refuses it when Providers or Access is set.
	DevUser *DevUser

	// SignUp decides who may create an account. The zero value is closed.
	SignUp SignUp
	// SeedRoles grants roles by email address, e.g. the first admin. A
	// seeded address may always sign up, whatever the sign-up policy.
	// Roles are added at sign-in and never removed by the package.
	SeedRoles map[string][]string

	// CookieName is the session cookie's name before the "__Host-" prefix.
	// Default "session".
	CookieName string
	// SessionIdleTTL ends a session unused for this long. Default 30 days.
	SessionIdleTTL time.Duration
	// SessionAbsoluteTTL ends a session this long after sign-in, however
	// active. Default 90 days.
	SessionAbsoluteTTL time.Duration

	// RatePerMinute and RateBurst limit the login, callback and logout
	// endpoints per client address. Defaults 30 and 10. A negative
	// RatePerMinute turns the limit off.
	RatePerMinute int
	RateBurst     int
	// ClientIPHeader names a header carrying the client address, e.g.
	// "CF-Connecting-IP". Set it only when nothing but the trusted proxy can
	// reach the app; otherwise clients can forge it. Empty uses RemoteAddr.
	ClientIPHeader string

	// Logger receives security-relevant events. Default slog.Default().
	Logger *slog.Logger
	// Now is the clock; tests replace it. Default time.Now.
	Now func() time.Time
}

// DevUser is the fixed user of the development authenticator.
type DevUser struct {
	Email string
	Name  string
	Roles []string
}

// Kit is a configured instance: handlers, middleware and the authenticator.
type Kit struct {
	store       Store
	log         *slog.Logger
	now         func() time.Time
	auth        Authenticator
	csrf        *http.CrossOriginProtection
	limiter     *rateLimiter
	providers   map[string]Provider
	order       []Provider
	seedRoles   map[string][]string
	signUp      SignUp
	baseURL     string
	prefix      string
	loginPath   string
	apiPrefixes []string
	cookieName  string
	loginCookie string
	ipHeader    string
	idleTTL     time.Duration
	absTTL      time.Duration
	secure      bool
	sessions    bool

	sweepMu   sync.Mutex
	lastSweep time.Time
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

// New validates cfg and builds a Kit. It makes no network calls: provider
// discovery and key fetches happen on first use.
func New(cfg Config) (*Kit, error) {
	if cfg.Store == nil {
		return nil, errors.New("authkit: Config.Store is required")
	}
	k := &Kit{
		store:       cfg.Store,
		log:         cfg.Logger,
		now:         cfg.Now,
		providers:   map[string]Provider{},
		seedRoles:   map[string][]string{},
		signUp:      cfg.SignUp,
		prefix:      strings.TrimRight(cfg.Prefix, "/"),
		loginPath:   cfg.LoginPath,
		apiPrefixes: cfg.APIPrefixes,
		ipHeader:    cfg.ClientIPHeader,
		idleTTL:     cfg.SessionIdleTTL,
		absTTL:      cfg.SessionAbsoluteTTL,
		csrf:        http.NewCrossOriginProtection(),
	}
	if k.log == nil {
		k.log = slog.Default()
	}
	if k.now == nil {
		k.now = time.Now
	}
	if k.prefix == "" {
		k.prefix = DefaultPrefix
	}
	if !strings.HasPrefix(k.prefix, "/") {
		return nil, fmt.Errorf("authkit: Prefix %q must start with /", cfg.Prefix)
	}
	if k.loginPath == "" {
		k.loginPath = DefaultLoginPath
	}
	if safeReturnPath(k.loginPath) != k.loginPath {
		return nil, fmt.Errorf("authkit: LoginPath %q must be a local path", cfg.LoginPath)
	}
	if k.apiPrefixes == nil {
		k.apiPrefixes = []string{"/api/"}
	}
	if k.idleTTL <= 0 {
		k.idleTTL = DefaultSessionIdleTTL
	}
	if k.absTTL <= 0 {
		k.absTTL = DefaultSessionAbsoluteTTL
	}
	for email, roles := range cfg.SeedRoles {
		k.seedRoles[normEmail(email)] = roles
	}
	for _, entry := range cfg.SignUp.Allow {
		if !strings.Contains(entry, ".") {
			return nil, fmt.Errorf("authkit: sign-up allow-list entry %q is not an address or domain", entry)
		}
	}
	if cfg.SignUp.Mode == SignUpAllowList && len(cfg.SignUp.Allow) == 0 {
		return nil, errors.New("authkit: sign-up allow-list is empty")
	}

	// Rate limiting.
	perMinute, burst := cfg.RatePerMinute, cfg.RateBurst
	if perMinute == 0 {
		perMinute = DefaultRatePerMinute
	}
	if burst <= 0 {
		burst = DefaultRateBurst
	}
	if perMinute > 0 {
		k.limiter = newRateLimiter(perMinute, burst, k.now)
	}

	// Cookies. The __Host- prefix makes browsers refuse the cookie unless it
	// is Secure, has Path=/ and no Domain, so a sibling subdomain cannot set it.
	name := cfg.CookieName
	if name == "" {
		name = DefaultCookieName
	}
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("authkit: CookieName %q must be lower-case letters, digits, - or _", name)
	}
	k.secure = true
	if cfg.BaseURL != "" {
		u, err := url.Parse(cfg.BaseURL)
		if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
			return nil, fmt.Errorf("authkit: BaseURL %q must be an origin such as https://app.example.com", cfg.BaseURL)
		}
		switch {
		case u.Scheme == "https":
		case u.Scheme == "http" && isLoopback(u.Hostname()):
			k.secure = false
		default:
			return nil, fmt.Errorf("authkit: BaseURL %q must be https (http is allowed for localhost only)", cfg.BaseURL)
		}
		k.baseURL = u.Scheme + "://" + u.Host
	}
	if k.secure {
		k.cookieName, k.loginCookie = "__Host-"+name, "__Host-"+name+"-login"
	} else {
		k.cookieName, k.loginCookie = name, name+"-login"
	}

	// Authenticators.
	hasReal := len(cfg.Providers) > 0 || cfg.Access != nil
	switch {
	case cfg.DevUser != nil && hasReal:
		return nil, errors.New("authkit: DevUser cannot be combined with Providers or Access; remove it outside local development")
	case cfg.DevUser != nil:
		dev, err := newDevAuthenticator(k, *cfg.DevUser)
		if err != nil {
			return nil, err
		}
		k.log.Warn("authkit: development authenticator is on; every request is signed in", "user", normEmail(cfg.DevUser.Email))
		k.auth = dev
	case !hasReal:
		return nil, errors.New("authkit: nothing to authenticate with; set Providers, Access or DevUser")
	}
	var chain []Authenticator
	if len(cfg.Providers) > 0 {
		if k.baseURL == "" {
			return nil, errors.New("authkit: BaseURL is required when Providers are set")
		}
		for _, p := range cfg.Providers {
			if p == nil || !nameRE.MatchString(p.Name()) {
				return nil, errors.New("authkit: provider names must be lower-case letters, digits, - or _")
			}
			if _, dup := k.providers[p.Name()]; dup {
				return nil, fmt.Errorf("authkit: duplicate provider %q", p.Name())
			}
			k.providers[p.Name()] = p
			k.order = append(k.order, p)
		}
		k.sessions = true
		chain = append(chain, sessionAuthenticator{k})
	}
	if cfg.Access != nil {
		a, err := newAccessAuthenticator(k, *cfg.Access)
		if err != nil {
			return nil, err
		}
		chain = append(chain, a)
	}
	if k.auth == nil {
		k.auth = Chain(chain...)
	}
	return k, nil
}

// Authenticator returns the configured answer to "who is this request?".
func (k *Kit) Authenticator() Authenticator { return k.auth }

// CallbackURL is the redirect URL to register with a provider.
func (k *Kit) CallbackURL(provider string) string {
	return k.baseURL + k.prefix + "/callback/" + provider
}

func isLoopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// newToken returns 256 bits of randomness, URL-safe.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails; panics if the OS source is broken
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// safeReturnPath returns p if it is a path on this site, else "/". It stops
// the login flow being used to bounce a user to another site.
func safeReturnPath(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.Contains(p, `\`) {
		return "/"
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return "/"
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	return p
}

// sweep deletes expired rows now and then, piggybacking on login traffic so
// the package needs no background goroutine.
func (k *Kit) sweep(r *http.Request) {
	now := k.now()
	k.sweepMu.Lock()
	due := now.Sub(k.lastSweep) >= sweepInterval
	if due {
		k.lastSweep = now
	}
	k.sweepMu.Unlock()
	if !due {
		return
	}
	if err := k.store.DeleteExpired(r.Context(), now); err != nil {
		k.log.Warn("authkit: deleting expired rows failed", "err", err)
	}
}
