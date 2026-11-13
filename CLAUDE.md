# authkit

A Go package that gives a stdlib `net/http` app its own login: Google and GitHub sign-in, server-side sessions, sign-up policy and per-app roles. It is a library embedded in each app (derp first), not a service. See README.md for integration, configuration and the threat model, and `docs/derp-integration.md` for the plan to adopt it in derp.

## Tech stack

- **Go**, stdlib `net/http` ServeMux patterns, `log/slog`, a `Config` struct with `ConfigFromEnv` for the env-var style the services use
- **Protocol and crypto are never hand-rolled:** `golang.org/x/oauth2` (code flow, PKCE), `github.com/coreos/go-oidc/v3` (discovery, ID token and Cloudflare Access token verification), `net/http.CrossOriginProtection` (CSRF)
- **Storage** behind the `Store` interface; `sqlitestore` is the SQLite implementation (`modernc.org/sqlite`), numbered SQL migrations tracked in `authkit_schema` because the host app owns `PRAGMA user_version`
- **Tests** run against fakes in `internal/authtest` (an OIDC issuer that signs real RS256 tokens, a GitHub, a Cloudflare Access certs endpoint). No network or credentials

## Layout

- `authkit.go` Config, `New`, cookie and return-path rules
- `user.go` types, the `Store` interface, sign-up policy, `resolve` (identity to user, account linking)
- `oidc.go`, `github.go` the two providers
- `authenticator.go` session cookie, Cloudflare Access and dev authenticators
- `middleware.go` `RequireUser`, `RequireRole`, `LoadUser`, CSRF check
- `handlers.go` login, callback, logout, me, providers
- `env.go` `ConfigFromEnv`
- `example/` runnable demo app

## Working here

```sh
task test        # fmt + vet + tests
task ci          # what the PR checks run (adds tidy-check, govulncheck, -race)
task lint
task run         # example app on http://localhost:8080 as a fixed dev user
```

- Every security rule has a test that fails for that reason. When adding a check, add the rejection case and assert on the log line or error code, not only on "it failed".
- Secrets use the `Secret` type so they cannot be printed. Never log a token, code, state, verifier or cookie value; `TestLogsHoldNoSecrets` guards the common paths.
- Changing a table means a new numbered file in `sqlitestore/migrations/`; never edit an applied one. A new `Store` method is a breaking change for apps that implement their own store.
- The README configuration table and the doc comment on `ConfigFromEnv` must match `env.go`.
- Provider names (`google`, `github`, `cloudflare-access`, `dev`) are stored in the identities table. Renaming one orphans every identity that used it.
