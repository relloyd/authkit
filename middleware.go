package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type ctxKey struct{}

// UserFrom returns the signed-in user placed in the context by RequireUser,
// RequireRole or LoadUser.
func UserFrom(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(ctxKey{}).(*User)
	return u, ok && u != nil
}

// WithUser returns ctx carrying u. Middleware does this for you; it is
// exported for handler tests.
func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, ctxKey{}, u)
}

// RequireUser admits only signed-in requests and puts the user in the
// context. A signed-out page load is redirected to the login page; anything
// else (API paths, fetch calls, non-GET methods) gets 401 JSON. It also
// rejects cross-site state-changing requests (CSRF).
func (k *Kit) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := k.authenticate(w, r)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
	})
}

// RequireRole is RequireUser plus a role check: a signed-in user without the
// role gets 403.
func (k *Kit) RequireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return k.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if u, _ := UserFrom(r.Context()); !u.HasRole(role) {
				k.deny(w, r, http.StatusForbidden, "forbidden")
				return
			}
			next.ServeHTTP(w, r)
		}))
	}
}

// LoadUser puts the user in the context when there is one and lets the
// request through either way, for pages that work signed in or out. It
// applies the same CSRF check as RequireUser.
func (k *Kit) LoadUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !k.sameOrigin(w, r) {
			return
		}
		if u, err := k.auth.Authenticate(r); err == nil {
			r = r.WithContext(WithUser(r.Context(), u))
		} else if !isRefusal(err) {
			k.log.Error("authkit: authentication failed", "err", err)
		}
		next.ServeHTTP(w, r)
	})
}

// isRefusal reports whether err is an expected "not admitted" answer, as
// opposed to a fault.
func isRefusal(err error) bool {
	return errors.Is(err, ErrNoUser) || errors.Is(err, ErrSignUpClosed) ||
		errors.Is(err, ErrUserDisabled) || errors.Is(err, ErrEmailNotVerified)
}

// authenticate resolves the user or writes the refusal and returns false.
func (k *Kit) authenticate(w http.ResponseWriter, r *http.Request) (*User, bool) {
	if !k.sameOrigin(w, r) {
		return nil, false
	}
	u, err := k.auth.Authenticate(r)
	switch {
	case err == nil:
		return u, true
	case errors.Is(err, ErrNoUser):
		if k.sessions && k.isPageLoad(r) {
			target := k.loginPath + "?return=" + url.QueryEscape(r.URL.RequestURI())
			http.Redirect(w, r, target, http.StatusSeeOther)
			return nil, false
		}
		k.deny(w, r, http.StatusUnauthorized, "unauthenticated")
	case isRefusal(err):
		// Known to a trusted front door (Cloudflare Access) but not admitted
		// by this app's sign-up policy, or disabled.
		k.deny(w, r, http.StatusForbidden, "forbidden")
	default:
		k.log.Error("authkit: authentication failed", "err", err)
		k.deny(w, r, http.StatusInternalServerError, "internal")
	}
	return nil, false
}

// sameOrigin rejects cross-site unsafe requests using net/http's
// CrossOriginProtection (Sec-Fetch-Site, falling back to Origin vs Host).
// Safe methods and non-browser clients pass.
func (k *Kit) sameOrigin(w http.ResponseWriter, r *http.Request) bool {
	if err := k.csrf.Check(r); err != nil {
		k.log.Warn("authkit: rejected cross-site request", "method", r.Method, "path", r.URL.Path)
		k.deny(w, r, http.StatusForbidden, "cross_site")
		return false
	}
	return true
}

func (k *Kit) isAPI(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, k.prefix+"/") {
		return true
	}
	for _, p := range k.apiPrefixes {
		if strings.HasPrefix(r.URL.Path, p) {
			return true
		}
	}
	return false
}

// isPageLoad reports whether the request is a browser navigating to a page,
// which is the only case where a redirect to the login page helps.
func (k *Kit) isPageLoad(r *http.Request) bool {
	if r.Method != http.MethodGet || k.isAPI(r) {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// deny writes a refusal: JSON for API paths, plain text for pages.
func (k *Kit) deny(w http.ResponseWriter, r *http.Request, status int, code string) {
	w.Header().Set("Cache-Control", "no-store")
	if k.isAPI(r) || !strings.Contains(r.Header.Get("Accept"), "text/html") {
		writeJSON(w, status, map[string]string{"error": code})
		return
	}
	http.Error(w, http.StatusText(status), status)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
