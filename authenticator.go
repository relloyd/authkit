package authkit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// Authenticator answers "who is this request?". It returns ErrNoUser when
// the request carries no valid credentials, ErrSignUpClosed or
// ErrUserDisabled when the person is known but not admitted, and any other
// error when the answer could not be determined.
type Authenticator interface {
	Authenticate(r *http.Request) (*User, error)
}

// AuthenticatorFunc adapts a function to an Authenticator.
type AuthenticatorFunc func(r *http.Request) (*User, error)

// Authenticate implements Authenticator.
func (f AuthenticatorFunc) Authenticate(r *http.Request) (*User, error) { return f(r) }

// Chain tries each authenticator in turn and returns the first user found.
// An authenticator that answers ErrNoUser passes to the next; any other
// error stops the chain.
func Chain(auths ...Authenticator) Authenticator {
	return AuthenticatorFunc(func(r *http.Request) (*User, error) {
		for _, a := range auths {
			u, err := a.Authenticate(r)
			if !errors.Is(err, ErrNoUser) {
				return u, err
			}
		}
		return nil, ErrNoUser
	})
}

// sessionAuthenticator reads the package's own session cookie.
type sessionAuthenticator struct{ k *Kit }

func (a sessionAuthenticator) Authenticate(r *http.Request) (*User, error) {
	k := a.k
	c, err := r.Cookie(k.cookieName)
	if err != nil || c.Value == "" {
		return nil, ErrNoUser
	}
	ctx := r.Context()
	hash := hashToken(c.Value)
	s, err := k.store.SessionByHash(ctx, hash)
	if errors.Is(err, ErrNotFound) {
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: load session: %w", err)
	}
	now := k.now()
	if !now.Before(s.ExpiresAt) || now.Sub(s.LastSeenAt) > k.idleTTL {
		k.deleteSession(ctx, hash)
		return nil, ErrNoUser
	}
	u, err := k.store.UserByID(ctx, s.UserID)
	if errors.Is(err, ErrNotFound) || (err == nil && u.Disabled) {
		k.deleteSession(ctx, hash)
		return nil, ErrNoUser
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: load user: %w", err)
	}
	// Record activity for the idle timeout, at most once a minute.
	if now.Sub(s.LastSeenAt) >= touchInterval {
		if err := k.store.TouchSession(ctx, hash, now); err != nil {
			k.log.Warn("authkit: touching session failed", "err", err)
		}
	}
	return u, nil
}

func (k *Kit) deleteSession(ctx context.Context, hash string) {
	if err := k.store.DeleteSession(ctx, hash); err != nil {
		k.log.Warn("authkit: deleting session failed", "err", err)
	}
}

// devAuthenticator signs every request in as one fixed user.
type devAuthenticator struct {
	k  *Kit
	id Identity
}

func newDevAuthenticator(k *Kit, d DevUser) (*devAuthenticator, error) {
	email := normEmail(d.Email)
	if !strings.Contains(email, "@") {
		return nil, fmt.Errorf("authkit: DevUser.Email %q is not an email address", d.Email)
	}
	// Seeding makes the dev user exempt from the sign-up policy and gives it
	// its roles through the same path as a real login.
	k.seedRoles[email] = append(k.seedRoles[email], d.Roles...)
	return &devAuthenticator{k: k, id: Identity{
		Provider: "dev", Subject: email, Email: email, EmailVerified: true, Name: d.Name,
	}}, nil
}

func (a *devAuthenticator) Authenticate(r *http.Request) (*User, error) {
	return a.k.resolve(r.Context(), a.id)
}

// AccessHeader is the header Cloudflare Access adds to every request it lets
// through, holding a signed token that names the user.
const AccessHeader = "Cf-Access-Jwt-Assertion"

// AccessConfig configures the Cloudflare Access authenticator.
type AccessConfig struct {
	// TeamDomain is the Zero Trust team domain, e.g.
	// "myteam.cloudflareaccess.com". It is the token issuer, and keys are
	// fetched from https://<TeamDomain>/cdn-cgi/access/certs.
	TeamDomain string
	// Audience is the Access application's audience (AUD) tag.
	Audience string
	// HTTPClient fetches the signing keys. Default: 10 second timeout.
	HTTPClient *http.Client
}

type accessAuthenticator struct {
	k        *Kit
	verifier *oidc.IDTokenVerifier
}

func newAccessAuthenticator(k *Kit, cfg AccessConfig) (*accessAuthenticator, error) {
	if cfg.TeamDomain == "" || cfg.Audience == "" {
		return nil, errors.New("authkit: Access needs TeamDomain and Audience")
	}
	issuer := strings.TrimRight(cfg.TeamDomain, "/")
	if !strings.Contains(issuer, "://") {
		issuer = "https://" + issuer
	}
	if u, err := url.Parse(issuer); err != nil || u.Host == "" {
		return nil, fmt.Errorf("authkit: Access TeamDomain %q is not a host name", cfg.TeamDomain)
	}
	client := cfg.HTTPClient
	if client == nil {
		client = defaultHTTPClient()
	}
	// The key set fetches lazily and refetches when it meets an unknown key
	// id, which is how Cloudflare's key rotation is picked up.
	keys := oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), client), issuer+"/cdn-cgi/access/certs")
	return &accessAuthenticator{
		k:        k,
		verifier: oidc.NewVerifier(issuer, keys, &oidc.Config{ClientID: cfg.Audience}),
	}, nil
}

func (a *accessAuthenticator) Authenticate(r *http.Request) (*User, error) {
	raw := r.Header.Get(AccessHeader)
	if raw == "" {
		return nil, ErrNoUser
	}
	// Verify checks the signature, issuer, audience and expiry.
	tok, err := a.verifier.Verify(r.Context(), raw)
	if err != nil {
		a.k.log.Warn("authkit: rejected Cloudflare Access token", "err", err)
		return nil, ErrNoUser
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := tok.Claims(&claims); err != nil || claims.Email == "" || tok.Subject == "" {
		// Service tokens carry no email; they are not people.
		return nil, ErrNoUser
	}
	// Access has already made the person prove the address (through its own
	// identity provider or a one-time code), so it counts as verified.
	return a.k.resolve(r.Context(), Identity{
		Provider: "cloudflare-access", Subject: tok.Subject,
		Email: claims.Email, EmailVerified: true,
	})
}
