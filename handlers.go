package authkit

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

// Error codes a failed login passes to the login page as ?error=<code>.
const (
	LoginErrDenied          = "denied"           // the user cancelled at the provider
	LoginErrInvalidState    = "invalid_state"    // stale, replayed or forged callback
	LoginErrProvider        = "provider_error"   // the provider exchange or token check failed
	LoginErrEmailUnverified = "email_unverified" // no verified address from the provider
	LoginErrSignUpClosed    = "signup_closed"    // genuine identity, not admitted by policy
	LoginErrDisabled        = "disabled"         // the account is disabled
	LoginErrInternal        = "internal"         // a fault on this side
)

// Register mounts the login handlers on mux under the configured prefix:
//
//	GET  {prefix}/login/{provider}     start a login
//	GET  {prefix}/callback/{provider}  finish it
//	POST {prefix}/logout               end the session
//	GET  {prefix}/me                   the signed-in user as JSON, or 401
//	GET  {prefix}/providers            the sign-in methods on offer, as JSON
func (k *Kit) Register(mux *http.ServeMux) {
	mux.Handle("GET "+k.prefix+"/login/{provider}", k.limit(http.HandlerFunc(k.handleLogin)))
	mux.Handle("GET "+k.prefix+"/callback/{provider}", k.limit(http.HandlerFunc(k.handleCallback)))
	mux.Handle("POST "+k.prefix+"/logout", k.limit(http.HandlerFunc(k.handleLogout)))
	mux.HandleFunc("GET "+k.prefix+"/me", k.handleMe)
	mux.HandleFunc("GET "+k.prefix+"/providers", k.handleProviders)
}

func (k *Kit) handleLogin(w http.ResponseWriter, r *http.Request) {
	p, ok := k.providers[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	k.sweep(r)
	a := AuthParams{
		RedirectURL: k.CallbackURL(p.Name()),
		State:       newToken(),
		Nonce:       newToken(),
		Verifier:    oauth2.GenerateVerifier(),
	}
	target, err := p.AuthCodeURL(r.Context(), a)
	if err != nil {
		k.log.Error("authkit: building authorisation URL failed", "provider", p.Name(), "err", err)
		k.failLogin(w, r, LoginErrProvider)
		return
	}
	err = k.store.CreatePendingLogin(r.Context(), PendingLogin{
		StateHash: hashToken(a.State),
		Provider:  p.Name(),
		Nonce:     a.Nonce,
		Verifier:  a.Verifier,
		ReturnTo:  safeReturnPath(r.URL.Query().Get("return")),
		ExpiresAt: k.now().Add(pendingLoginTTL),
	})
	if err != nil {
		k.log.Error("authkit: saving pending login failed", "err", err)
		k.failLogin(w, r, LoginErrInternal)
		return
	}
	// The state also goes in a cookie, binding the login to this browser:
	// without it an attacker could start a login and feed the victim the
	// callback link, signing the victim in to the attacker's account.
	k.setCookie(w, k.loginCookie, a.State, int(pendingLoginTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, target, http.StatusFound)
}

func (k *Kit) handleCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer") // the URL holds the code
	p, ok := k.providers[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	cookie, err := r.Cookie(k.loginCookie)
	k.setCookie(w, k.loginCookie, "", -1)
	if state == "" || err != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) != 1 {
		k.log.Warn("authkit: callback state does not match this browser", "provider", p.Name())
		k.failLogin(w, r, LoginErrInvalidState)
		return
	}
	pending, err := k.store.TakePendingLogin(ctx, hashToken(state))
	if err != nil && !errors.Is(err, ErrNotFound) {
		k.log.Error("authkit: loading pending login failed", "err", err)
		k.failLogin(w, r, LoginErrInternal)
		return
	}
	if err != nil || pending.Provider != p.Name() || !k.now().Before(pending.ExpiresAt) {
		k.log.Warn("authkit: callback state unknown, expired or already used", "provider", p.Name())
		k.failLogin(w, r, LoginErrInvalidState)
		return
	}
	if q.Get("error") != "" {
		// The value is the provider's, shown to nobody; log a bounded copy.
		k.log.Info("authkit: provider returned an error", "provider", p.Name(), "error", truncate(q.Get("error"), 64))
		k.failLogin(w, r, LoginErrDenied)
		return
	}
	id, err := p.Exchange(ctx, AuthParams{
		RedirectURL: k.CallbackURL(p.Name()),
		State:       state,
		Nonce:       pending.Nonce,
		Verifier:    pending.Verifier,
	}, q.Get("code"))
	if err != nil {
		if errors.Is(err, ErrEmailNotVerified) {
			k.log.Warn("authkit: login refused: no verified email", "provider", p.Name())
			k.failLogin(w, r, LoginErrEmailUnverified)
			return
		}
		k.log.Warn("authkit: login failed at the provider", "provider", p.Name(), "err", err)
		k.failLogin(w, r, LoginErrProvider)
		return
	}
	u, err := k.resolve(ctx, id)
	switch {
	case err == nil:
	case errors.Is(err, ErrSignUpClosed):
		k.log.Warn("authkit: login refused by sign-up policy", "provider", p.Name(), "email", normEmail(id.Email))
		k.failLogin(w, r, LoginErrSignUpClosed)
		return
	case errors.Is(err, ErrUserDisabled):
		k.log.Warn("authkit: login refused: user disabled", "provider", p.Name(), "email", normEmail(id.Email))
		k.failLogin(w, r, LoginErrDisabled)
		return
	case errors.Is(err, ErrEmailNotVerified):
		k.failLogin(w, r, LoginErrEmailUnverified)
		return
	default:
		k.log.Error("authkit: resolving user failed", "err", err)
		k.failLogin(w, r, LoginErrInternal)
		return
	}
	if err := k.startSession(w, r, u); err != nil {
		k.log.Error("authkit: starting session failed", "err", err)
		k.failLogin(w, r, LoginErrInternal)
		return
	}
	k.log.Info("authkit: signed in", "provider", p.Name(), "user", u.ID)
	http.Redirect(w, r, safeReturnPath(pending.ReturnTo), http.StatusSeeOther)
}

// startSession issues a fresh session id on every sign-in (so a planted
// cookie is never adopted) and drops any session the browser already had.
func (k *Kit) startSession(w http.ResponseWriter, r *http.Request, u *User) error {
	if old, err := r.Cookie(k.cookieName); err == nil && old.Value != "" {
		k.deleteSession(r.Context(), hashToken(old.Value))
	}
	token, now := newToken(), k.now()
	err := k.store.CreateSession(r.Context(), Session{
		IDHash:     hashToken(token),
		UserID:     u.ID,
		CreatedAt:  now,
		LastSeenAt: now,
		ExpiresAt:  now.Add(k.absTTL),
	})
	if err != nil {
		return err
	}
	k.setCookie(w, k.cookieName, token, int(k.absTTL.Seconds()))
	return nil
}

func (k *Kit) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !k.sameOrigin(w, r) {
		return
	}
	if c, err := r.Cookie(k.cookieName); err == nil && c.Value != "" {
		k.deleteSession(r.Context(), hashToken(c.Value))
	}
	k.setCookie(w, k.cookieName, "", -1)
	w.Header().Set("Cache-Control", "no-store")
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, k.loginPath, http.StatusSeeOther) // a plain <form> post
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (k *Kit) handleMe(w http.ResponseWriter, r *http.Request) {
	u, err := k.auth.Authenticate(r)
	switch {
	case err == nil:
		if u.Roles == nil {
			u.Roles = []string{}
		}
		writeJSON(w, http.StatusOK, u)
	case errors.Is(err, ErrNoUser):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
	case isRefusal(err):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	default:
		k.log.Error("authkit: authentication failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}

// ProviderInfo describes one sign-in method for a login page.
type ProviderInfo struct {
	Name  string `json:"name"`
	Label string `json:"label"`
	// LoginURL starts the login; append ?return=<path> to come back to a
	// particular page.
	LoginURL string `json:"login_url"`
}

// ProviderList returns the sign-in methods on offer, in configured order.
func (k *Kit) ProviderList() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(k.order))
	for _, p := range k.order {
		out = append(out, ProviderInfo{Name: p.Name(), Label: p.Label(), LoginURL: k.prefix + "/login/" + p.Name()})
	}
	return out
}

func (k *Kit) handleProviders(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"providers": k.ProviderList()})
}

func (k *Kit) failLogin(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, k.loginPath+"?error="+url.QueryEscape(code), http.StatusSeeOther)
}

func (k *Kit) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   k.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// limit applies the per-client rate limit.
func (k *Kit) limit(next http.Handler) http.Handler {
	if k.limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wait, ok := k.limiter.allow(k.clientIP(r)); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(wait))
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (k *Kit) clientIP(r *http.Request) string {
	if k.ipHeader != "" {
		if v := strings.TrimSpace(r.Header.Get(k.ipHeader)); v != "" {
			return v
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
