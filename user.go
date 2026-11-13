package authkit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Errors returned by the package and by Store implementations.
var (
	// ErrNotFound is returned by a Store when a row does not exist.
	ErrNotFound = errors.New("authkit: not found")
	// ErrConflict is returned by a Store when a unique key already exists.
	ErrConflict = errors.New("authkit: already exists")
	// ErrNoUser is returned by an Authenticator when the request carries no
	// valid credentials. It is the "nobody is signed in" answer, not a failure.
	ErrNoUser = errors.New("authkit: no authenticated user")
	// ErrSignUpClosed means the identity is genuine but the sign-up policy
	// does not admit a new account for it.
	ErrSignUpClosed = errors.New("authkit: sign-up is not open to this address")
	// ErrEmailNotVerified means the provider did not vouch for the address.
	ErrEmailNotVerified = errors.New("authkit: provider did not supply a verified email address")
	// ErrUserDisabled means the account exists but has been disabled.
	ErrUserDisabled = errors.New("authkit: user is disabled")
)

// Identity is what a login provider asserts about the person who signed in.
// Provider and Subject together are the stable key; Email is used only to
// link a first-time identity to an existing account.
type Identity struct {
	Provider      string
	Subject       string
	Email         string
	Name          string
	EmailVerified bool
}

// User is an account in one app. Roles are plain strings owned by the app.
type User struct {
	CreatedAt time.Time `json:"-"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Roles     []string  `json:"roles"`
	ID        int64     `json:"id"`
	Disabled  bool      `json:"-"`
}

// HasRole reports whether the user holds role.
func (u *User) HasRole(role string) bool {
	return u != nil && slices.Contains(u.Roles, role)
}

// Session is a server-side session. Only the SHA-256 of the cookie value is
// stored, so a copy of the database cannot be replayed as a cookie.
type Session struct {
	CreatedAt  time.Time
	LastSeenAt time.Time
	// ExpiresAt is the absolute expiry, fixed when the session is created.
	ExpiresAt time.Time
	IDHash    string
	UserID    int64
}

// PendingLogin is the server-side half of a login in progress: everything the
// callback needs that must not be trusted to the browser.
type PendingLogin struct {
	ExpiresAt time.Time
	StateHash string
	Provider  string
	Nonce     string
	Verifier  string
	ReturnTo  string
}

// Store is the persistence the package needs. The app owns the database;
// sqlitestore is a ready implementation, and an app may write its own over
// its existing user table.
//
// Lookups return ErrNotFound when there is no row. CreateUser and
// LinkIdentity return ErrConflict when the unique key is already taken.
// Emails passed in are already lower-cased.
type Store interface {
	UserByID(ctx context.Context, id int64) (*User, error)
	UserByEmail(ctx context.Context, email string) (*User, error)
	UserByIdentity(ctx context.Context, provider, subject string) (*User, error)
	CreateUser(ctx context.Context, email, name string, roles []string) (*User, error)
	// LinkIdentity records that (id.Provider, id.Subject) signs in as userID.
	LinkIdentity(ctx context.Context, userID int64, id Identity) error
	// AddRoles grants roles the user does not already hold.
	AddRoles(ctx context.Context, userID int64, roles []string) error

	CreateSession(ctx context.Context, s Session) error
	SessionByHash(ctx context.Context, idHash string) (*Session, error)
	TouchSession(ctx context.Context, idHash string, lastSeen time.Time) error
	DeleteSession(ctx context.Context, idHash string) error
	DeleteUserSessions(ctx context.Context, userID int64) error

	CreatePendingLogin(ctx context.Context, p PendingLogin) error
	// TakePendingLogin returns the pending login and deletes it in one step,
	// so a state value can be used only once.
	TakePendingLogin(ctx context.Context, stateHash string) (*PendingLogin, error)

	// DeleteExpired removes pending logins and sessions past their expiry.
	DeleteExpired(ctx context.Context, now time.Time) error
}

// SignUpMode says who may create an account by signing in for the first time.
type SignUpMode int

const (
	// SignUpClosed admits nobody new. Existing users and addresses named in
	// Config.SeedRoles can still sign in. This is the zero value.
	SignUpClosed SignUpMode = iota
	// SignUpAllowList admits the addresses and domains in SignUp.Allow.
	SignUpAllowList
	// SignUpOpen admits anyone with a verified email address.
	SignUpOpen
)

// SignUp is the per-app sign-up policy.
type SignUp struct {
	// Allow holds full addresses ("ada@example.com") and domains
	// ("@example.com" or "example.com"). Used only with SignUpAllowList.
	// Domains match exactly; subdomains are not included.
	Allow []string
	Mode  SignUpMode
}

func (s SignUp) allows(email string) bool {
	switch s.Mode {
	case SignUpOpen:
		return true
	case SignUpAllowList:
		_, domain, ok := strings.Cut(email, "@")
		if !ok {
			return false
		}
		for _, entry := range s.Allow {
			entry = normEmail(entry)
			if i := strings.LastIndex(entry, "@"); i > 0 {
				if entry == email {
					return true
				}
			} else if strings.TrimPrefix(entry, "@") == domain {
				return true
			}
		}
	}
	return false
}

func normEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// resolve turns a provider's identity into this app's user: an identity seen
// before maps straight to its user; a new identity links to the account with
// the same verified email, or creates one if the sign-up policy allows.
func (k *Kit) resolve(ctx context.Context, id Identity) (*User, error) {
	id.Email = normEmail(id.Email)
	if id.Provider == "" || id.Subject == "" {
		return nil, errors.New("authkit: identity has no provider or subject")
	}
	u, err := k.store.UserByIdentity(ctx, id.Provider, id.Subject)
	switch {
	case err == nil:
	case errors.Is(err, ErrNotFound):
		// Only a verified address may claim or create an account.
		if !id.EmailVerified || !strings.Contains(id.Email, "@") {
			return nil, ErrEmailNotVerified
		}
		if u, err = k.userForEmail(ctx, id); err != nil {
			return nil, err
		}
		if err := k.store.LinkIdentity(ctx, u.ID, id); err != nil && !errors.Is(err, ErrConflict) {
			return nil, fmt.Errorf("authkit: link identity: %w", err)
		}
	default:
		return nil, fmt.Errorf("authkit: look up identity: %w", err)
	}
	if u.Disabled {
		return nil, ErrUserDisabled
	}
	var missing []string
	for _, role := range k.seedRoles[u.Email] {
		if !u.HasRole(role) {
			missing = append(missing, role)
		}
	}
	if len(missing) > 0 {
		if err := k.store.AddRoles(ctx, u.ID, missing); err != nil {
			return nil, fmt.Errorf("authkit: seed roles: %w", err)
		}
		u.Roles = append(u.Roles, missing...)
		slices.Sort(u.Roles)
	}
	return u, nil
}

func (k *Kit) userForEmail(ctx context.Context, id Identity) (*User, error) {
	u, err := k.store.UserByEmail(ctx, id.Email)
	if err == nil {
		return u, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("authkit: look up email: %w", err)
	}
	if _, seeded := k.seedRoles[id.Email]; !seeded && !k.signUp.allows(id.Email) {
		return nil, ErrSignUpClosed
	}
	u, err = k.store.CreateUser(ctx, id.Email, id.Name, nil)
	if errors.Is(err, ErrConflict) {
		// Lost a race with another request for the same address.
		u, err = k.store.UserByEmail(ctx, id.Email)
	}
	if err != nil {
		return nil, fmt.Errorf("authkit: create user: %w", err)
	}
	return u, nil
}
