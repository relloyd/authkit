// Command example is the smallest useful app on authkit: a public home page,
// a login page, a page for any signed-in user and a page for admins.
//
// Run it with no provider credentials using the development authenticator:
//
//	AUTH_MODE=dev AUTH_DEV_USER=dev@example.test AUTH_DEV_ROLES=admin go run ./example
//
// or with real providers (see the README for creating the OAuth clients):
//
//	AUTH_MODE=session AUTH_BASE_URL=http://localhost:8080 AUTH_SIGNUP=open \
//	AUTH_GITHUB_CLIENT_ID=... AUTH_GITHUB_CLIENT_SECRET=... go run ./example
package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/relloyd/authkit"
	"github.com/relloyd/authkit/sqlitestore"
)

//go:embed web/*.html
var web embed.FS

var pages = template.Must(template.ParseFS(web, "web/*.html"))

// loginErrors turns the ?error= codes into something to show a person.
var loginErrors = map[string]string{
	authkit.LoginErrDenied:          "Sign-in was cancelled.",
	authkit.LoginErrInvalidState:    "That sign-in link had expired. Please try again.",
	authkit.LoginErrProvider:        "The sign-in provider returned an error. Please try again.",
	authkit.LoginErrEmailUnverified: "That account has no verified email address.",
	authkit.LoginErrSignUpClosed:    "This app is not open to that address.",
	authkit.LoginErrDisabled:        "That account has been disabled.",
	authkit.LoginErrInternal:        "Something went wrong on our side. Please try again.",
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	addr := envOr("ADDR", "localhost:8080")
	dbPath := envOr("DB_PATH", "example.db")

	// The app's own database handle; authkit's tables go in the same file.
	db, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := sqlitestore.New(ctx, db)
	if err != nil {
		return err
	}

	cfg, err := authkit.ConfigFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	cfg.Store = store
	cfg.Logger = log
	auth, err := authkit.New(cfg)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	auth.Register(mux) // /auth/login/{provider}, /auth/callback/{provider}, /auth/logout, /auth/me
	mux.Handle("GET /{$}", auth.LoadUser(page("home", auth)))
	mux.Handle("GET /login", auth.LoadUser(page("login", auth)))
	mux.Handle("GET /app", auth.RequireUser(page("app", auth)))
	mux.Handle("GET /admin", auth.RequireRole("admin")(page("admin", auth)))

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	log.Info("listening", "url", "http://"+addr)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// page renders one template with the signed-in user, if any.
func page(name string, auth *authkit.Kit) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _ := authkit.UserFrom(r.Context())
		data := struct {
			User      *authkit.User
			Providers []authkit.ProviderInfo
			Return    string
			Error     string
		}{
			User:      user,
			Providers: auth.ProviderList(),
			Return:    r.URL.Query().Get("return"), // authkit validates it; never redirect to it yourself
			Error:     loginErrors[r.URL.Query().Get("error")],
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := pages.ExecuteTemplate(w, name, data); err != nil {
			slog.Error("render", "page", name, "err", err)
		}
	})
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
