package authkit

import (
	"context"
	"log/slog"
)

// AuthParams are the per-login values the Kit generates and a Provider must
// bind into the flow.
type AuthParams struct {
	// RedirectURL is this app's callback URL for the provider.
	RedirectURL string
	// State ties the callback to the login that started it.
	State string
	// Nonce is echoed inside an OIDC ID token; unused by plain OAuth 2.
	Nonce string
	// Verifier is the PKCE code verifier. The authorisation URL carries its
	// S256 challenge; the token exchange carries the verifier itself.
	Verifier string
}

// Provider is one sign-in method.
type Provider interface {
	// Name is the URL-safe identifier used in /auth/login/{name} and stored
	// with each identity, e.g. "google". It must never change once in use.
	Name() string
	// Label is the human name for a button, e.g. "Google".
	Label() string
	// AuthCodeURL returns where to send the browser to sign in.
	AuthCodeURL(ctx context.Context, p AuthParams) (string, error)
	// Exchange swaps the callback's code for a verified Identity. It returns
	// ErrEmailNotVerified when the provider does not vouch for an address.
	Exchange(ctx context.Context, p AuthParams, code string) (Identity, error)
}

// Secret is a string that will not print itself: formatting it, logging it
// with slog, or marshalling it to JSON yields "[redacted]". Use Reveal for
// the value.
type Secret string

const redacted = "[redacted]"

// Reveal returns the secret value.
func (s Secret) Reveal() string { return string(s) }

// String implements fmt.Stringer.
func (Secret) String() string { return redacted }

// GoString implements fmt.GoStringer, covering %#v.
func (Secret) GoString() string { return redacted }

// LogValue implements slog.LogValuer.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText covers encoding/json and anything else text-based.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }
