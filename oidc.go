package authkit

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// GoogleIssuer is Google's OpenID Connect issuer.
const GoogleIssuer = "https://accounts.google.com"

// OIDCConfig configures a generic OpenID Connect provider.
type OIDCConfig struct {
	// Name and Label as in Provider. Name defaults to "oidc".
	Name  string
	Label string
	// Issuer is the issuer URL; discovery is fetched from
	// Issuer + "/.well-known/openid-configuration".
	Issuer       string
	ClientID     string
	ClientSecret Secret
	// Scopes default to openid, email, profile.
	Scopes []string
	// HTTPClient is used for discovery, keys and the token exchange.
	// Default: a client with a 10 second timeout.
	HTTPClient *http.Client
}

// OIDC is a Provider for any OpenID Connect issuer.
type OIDC struct {
	cfg      OIDCConfig
	mu       sync.Mutex
	provider *oidc.Provider
}

// NewOIDC returns an OpenID Connect provider. Discovery is deferred to first
// use, so an unreachable issuer does not stop the app starting.
func NewOIDC(cfg OIDCConfig) (*OIDC, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("authkit: OIDC provider needs Issuer, ClientID and ClientSecret")
	}
	if cfg.Name == "" {
		cfg.Name = "oidc"
	}
	if cfg.Label == "" {
		cfg.Label = cfg.Name
	}
	if cfg.Scopes == nil {
		cfg.Scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient()
	}
	return &OIDC{cfg: cfg}, nil
}

// Google returns the OIDC provider for Google accounts, named "google".
func Google(clientID string, clientSecret Secret) (*OIDC, error) {
	return NewOIDC(OIDCConfig{
		Name: "google", Label: "Google", Issuer: GoogleIssuer,
		ClientID: clientID, ClientSecret: clientSecret,
	})
}

func defaultHTTPClient() *http.Client { return &http.Client{Timeout: 10 * time.Second} }

// Name implements Provider.
func (o *OIDC) Name() string { return o.cfg.Name }

// Label implements Provider.
func (o *OIDC) Label() string { return o.cfg.Label }

// discover fetches and caches the issuer's metadata. A failure is not
// cached, so the next login tries again.
func (o *OIDC) discover() (*oidc.Provider, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return o.provider, nil
	}
	// The provider keeps this context for later key fetches, so it must not
	// be a request's context. The client's timeout bounds each call.
	ctx := oidc.ClientContext(context.Background(), o.cfg.HTTPClient)
	p, err := oidc.NewProvider(ctx, o.cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("authkit: %s discovery: %w", o.cfg.Name, err)
	}
	o.provider = p
	return p, nil
}

func (o *OIDC) oauth(p *oidc.Provider, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret.Reveal(),
		Endpoint:     p.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       o.cfg.Scopes,
	}
}

// AuthCodeURL implements Provider.
func (o *OIDC) AuthCodeURL(_ context.Context, a AuthParams) (string, error) {
	p, err := o.discover()
	if err != nil {
		return "", err
	}
	return o.oauth(p, a.RedirectURL).AuthCodeURL(a.State,
		oauth2.S256ChallengeOption(a.Verifier), oidc.Nonce(a.Nonce)), nil
}

// Exchange implements Provider. The ID token's signature, issuer, audience
// and expiry are checked by go-oidc; the nonce and email_verified here.
func (o *OIDC) Exchange(ctx context.Context, a AuthParams, code string) (Identity, error) {
	p, err := o.discover()
	if err != nil {
		return Identity{}, err
	}
	ctx = oidc.ClientContext(ctx, o.cfg.HTTPClient)
	tok, err := o.oauth(p, a.RedirectURL).Exchange(ctx, code, oauth2.VerifierOption(a.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("authkit: %s code exchange: %w", o.cfg.Name, err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Identity{}, fmt.Errorf("authkit: %s returned no id_token", o.cfg.Name)
	}
	idt, err := p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID}).Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("authkit: %s id_token: %w", o.cfg.Name, err)
	}
	if a.Nonce == "" || subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(a.Nonce)) != 1 {
		return Identity{}, fmt.Errorf("authkit: %s id_token nonce does not match this login", o.cfg.Name)
	}
	var claims struct {
		Email         string   `json:"email"`
		Name          string   `json:"name"`
		EmailVerified flexBool `json:"email_verified"`
	}
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("authkit: %s id_token claims: %w", o.cfg.Name, err)
	}
	if claims.Email == "" || !claims.EmailVerified {
		return Identity{}, ErrEmailNotVerified
	}
	return Identity{
		Provider: o.cfg.Name, Subject: idt.Subject,
		Email: claims.Email, EmailVerified: true, Name: claims.Name,
	}, nil
}

// flexBool accepts true and "true": some issuers send email_verified as a
// string.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	*b = flexBool(strings.Trim(string(data), `"`) == "true")
	return nil
}
