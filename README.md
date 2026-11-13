# authkit

Login for small Go web apps: "Continue with Google", "Continue with GitHub", server-side sessions, a sign-up policy and per-app roles, for apps built on the standard library's `net/http`.

**What it is.** A Go package you embed in each app. Each app keeps its own users and sessions in its own database (SQLite support is included). There is nothing extra to deploy and no shared service that can take every app down at once.

**What it is not.**

- Not an identity provider or a single sign-on service. Signing in to one app does not sign you in to another.
- Not a password system. There are no passwords, password resets or email sending. People sign in with an account they already have.
- Not a user-management UI. It stores users and roles; your admin page decides what to show and change.
- Not an implementation of OAuth or of any cryptography. The protocol work is done by [`golang.org/x/oauth2`](https://pkg.go.dev/golang.org/x/oauth2) and [`github.com/coreos/go-oidc/v3`](https://pkg.go.dev/github.com/coreos/go-oidc/v3).

The package answers one question, "who is this request?", in three interchangeable ways, chosen by configuration:

| Mode | Who signs the user in | Use it when |
|---|---|---|
| `session` | this package: Google or GitHub, then its own session cookie | the app is exposed directly and has its own login page |
| `access` | Cloudflare Access, in front of the app; the package verifies the token Access attaches to each request | the app sits behind Access |
| `dev` | nobody: every request is one fixed user | local development only |

Handlers see a `*authkit.User` in the request context whichever mode is on, and users are matched by verified email, so an app can start behind Cloudflare Access and move to its own login later without changing handlers or losing anyone's account. `access,session` accepts both during the move.

## Integration

```go
store, err := sqlitestore.New(ctx, db)          // db is the app's own *sql.DB
cfg, err := authkit.ConfigFromEnv(os.Getenv)    // AUTH_MODE, AUTH_BASE_URL, ...
cfg.Store = store
auth, err := authkit.New(cfg)

mux := http.NewServeMux()
auth.Register(mux)                                             // /auth/login/{provider}, /auth/callback/{provider}, /auth/logout, /auth/me
mux.Handle("GET /login", loginPage)                            // your page, with links to /auth/login/google and /auth/login/github
mux.Handle("/api/", auth.RequireUser(api))                     // 401 JSON when signed out
mux.Handle("GET /admin", auth.RequireRole("admin")(adminPage)) // 403 without the role

user, ok := authkit.UserFrom(r.Context())                      // inside a handler
```

`example/` is a complete runnable app. `task run` starts it at <http://localhost:8080> in `dev` mode, with no provider credentials.

### Routes

`Register` mounts these under the prefix (default `/auth`):

| Route | Purpose |
|---|---|
| `GET /auth/login/{provider}` | Starts a login and redirects to the provider. Add `?return=/some/path` to come back to a page. |
| `GET /auth/callback/{provider}` | The provider redirects here. Checks everything, starts the session, redirects to the return path. |
| `POST /auth/logout` | Deletes the session. Answers 204, or redirects to the login page for a plain HTML form. |
| `GET /auth/me` | The signed-in user as JSON (`id`, `email`, `name`, `roles`), or 401. |
| `GET /auth/providers` | The sign-in methods on offer, for a login page built in JavaScript. |

A failed login redirects to your login page with `?error=<code>`, where the code is one of `denied`, `invalid_state`, `provider_error`, `email_unverified`, `signup_closed`, `disabled` or `internal`. Show your own wording; `example/main.go` has a set.

### Middleware

- `RequireUser` admits signed-in requests. Signed out, a browser page load is redirected to the login page with the page remembered; an API path (default prefix `/api/`), a `fetch` call or any non-GET request gets `401 {"error":"unauthenticated"}`.
- `RequireRole("admin")` is `RequireUser` plus a role check; without the role the answer is 403.
- `LoadUser` puts the user in the context if there is one and lets the request through either way.

All three reject cross-site state-changing requests.

### Users, roles and sign-up

- A user is created the first time someone signs in, if the sign-up policy admits their address: `open` (anyone with a verified address), `allowlist` (named addresses and domains), or `closed` (nobody new; the default).
- The same person arriving through Google and through GitHub is one user, because both report the same verified address. Each sign-in method is recorded as an identity keyed by the provider's own account id, so a later change of address at the provider does not move them to a different account.
- Roles are strings your app chooses. `AUTH_ADMIN_EMAILS` (or `Config.SeedRoles`) grants roles by address at sign-in, which is how the first admin gets in; a seeded address can always sign up. Grant and remove other roles through the store (`AddRoles`, `SetRoles`).
- `sqlitestore` also has `ListUsers`, `SetDisabled` and `DeleteUser` for an admin page. Its tables are prefixed `authkit_` and live in your app's database file. Your own tables refer to `authkit_users.id`.
- To keep users in a table you already have, implement the `Store` interface yourself.

## Configuration

`ConfigFromEnv` reads these. Everything can also be set directly on `authkit.Config`, which has a few more options (`Prefix`, `LoginPath`, `APIPrefixes`, `CookieName`, rate limits, `SeedRoles` for roles other than `admin`).

| Variable | Default | Meaning |
|---|---|---|
| `AUTH_MODE` | required | `session`, `access`, `access,session` or `dev`. Settings for modes that are not selected are ignored, so this one value switches mode while the secrets stay in place. |
| `AUTH_BASE_URL` | required for `session` | The app's public origin, e.g. `https://derp.example.com`. Must be `https`, except `http://localhost`. |
| `AUTH_GOOGLE_CLIENT_ID`, `AUTH_GOOGLE_CLIENT_SECRET` | none | Set both to offer Google. |
| `AUTH_GITHUB_CLIENT_ID`, `AUTH_GITHUB_CLIENT_SECRET` | none | Set both to offer GitHub. `session` needs at least one provider. |
| `AUTH_ACCESS_TEAM_DOMAIN` | required for `access` | The Zero Trust team domain, e.g. `myteam.cloudflareaccess.com`. |
| `AUTH_ACCESS_AUD` | required for `access` | The Access application's audience (AUD) tag. |
| `AUTH_DEV_USER` | required for `dev` | Email of the fixed user. Startup fails if this is set in any other mode. |
| `AUTH_DEV_ROLES` | none | Comma-separated roles for the dev user. |
| `AUTH_SIGNUP` | `closed` | `closed`, `allowlist` or `open`. |
| `AUTH_SIGNUP_ALLOW` | none | For `allowlist`: comma-separated addresses and domains (`ada@example.com, example.org`). Domains match exactly, not subdomains. |
| `AUTH_ADMIN_EMAILS` | none | Comma-separated addresses given the `admin` role when they sign in. |
| `AUTH_SESSION_IDLE` | `720h` (30 days) | A session unused for this long ends. |
| `AUTH_SESSION_MAX` | `2160h` (90 days) | A session ends this long after sign-in, however active. |
| `AUTH_CLIENT_IP_HEADER` | none | Header holding the client address for rate limiting, e.g. `CF-Connecting-IP`. Set it only when nothing but your proxy can reach the app. |

The client secrets are the only secrets. There is no session signing key, because session cookies are random ids looked up in the database, not signed tokens.

## Provider setup

Each provider needs to know exactly where to send people back to. The callback URL is always:

```
<AUTH_BASE_URL>/auth/callback/<provider>
```

For example `https://derp.example.com/auth/callback/google` and `https://derp.example.com/auth/callback/github`. For local testing, `http://localhost:8080/auth/callback/...`. `auth.CallbackURL("google")` returns the exact value.

Console layouts change; the steps below were written in November 2026 and not re-checked against the live consoles.

### Google

1. Open the [Google Cloud console](https://console.cloud.google.com/) and create a project (or pick one). One project can serve all your apps.
2. Go to **Google Auth Platform** (older consoles: **APIs & Services > OAuth consent screen**). Fill in **Branding**: app name, support email, and your domain under authorised domains.
3. Under **Audience**, choose **External**. While the status is **Testing**, only the test users you list can sign in; choose **Publish app** to allow anyone. The scopes used here (`openid`, `email`, `profile`) are non-sensitive, so no Google review is needed.
4. Under **Clients**, choose **Create client**, type **Web application**.
5. Under **Authorised redirect URIs**, add the callback URL for each app and for localhost. A Google client accepts several, so one client can serve every hostname. Leave **Authorised JavaScript origins** empty.
6. Copy the client ID and client secret into `AUTH_GOOGLE_CLIENT_ID` and `AUTH_GOOGLE_CLIENT_SECRET`. Google shows the secret once.

### GitHub

1. On GitHub, go to **Settings > Developer settings > OAuth Apps > New OAuth App**. Choose an OAuth App, not a GitHub App.
2. **Application name** is what people see on the consent screen. **Homepage URL** is the app's address.
3. **Authorization callback URL** is the callback URL above.
4. Register, then **Generate a new client secret**. Copy the client ID and the secret into `AUTH_GITHUB_CLIENT_ID` and `AUTH_GITHUB_CLIENT_SECRET`. GitHub shows the secret once.

**A GitHub OAuth app has a single callback URL, so each app hostname needs its own OAuth app**, and so does localhost. Two apps on two hostnames means two GitHub OAuth apps and two pairs of credentials; do not try to share one.

The package asks GitHub for the `read:user` and `user:email` scopes and uses the account's primary address, which must be verified. Someone whose GitHub account has no verified primary address cannot sign in with it.

## Threat model

### What the package defends against

| Threat | Defence |
|---|---|
| Forged or replayed login callback | A random `state` per login, stored server-side (hashed), single use, expiring after 10 minutes. |
| Login CSRF (an attacker feeds the victim a callback for the attacker's account) | The `state` is also held in a cookie in the browser that started the login; a callback arriving in any other browser is refused. |
| Stolen authorisation code | PKCE (S256). The verifier never leaves the server. |
| Forged or substituted ID token (Google) | Signature checked against the issuer's published keys; issuer, audience and expiry checked; `nonce` tied to this login. |
| Account takeover through an unverified address | Only an address the provider marks verified can create or link an account. GitHub: the primary, verified address only. |
| Takeover by changing an address at the provider | Identities are keyed by provider and the provider's account id, never by email alone. |
| Session theft from the database or a backup | Only a SHA-256 of the session id is stored. |
| Session theft by script, or a planted cookie | The cookie is `HttpOnly`, `Secure`, `SameSite=Lax` with the `__Host-` prefix (no sibling subdomain can set it). A new id is issued on every sign-in. |
| Sessions that live for ever | Idle and absolute expiry; deleting the row, disabling the user or `DeleteUserSessions` ends a session at once. |
| CSRF on state-changing requests | Cross-site `POST`/`PUT`/`PATCH`/`DELETE` are refused using `Sec-Fetch-Site`, falling back to `Origin` against `Host` (Go's `http.CrossOriginProtection`). |
| Open redirect after login | The return path must be a path on the same site; anything else becomes `/`. |
| Forged Cloudflare Access header | The token's signature, issuer (team domain), audience tag and expiry are verified on every request. A missing or bad token is "not signed in". |
| The dev user reaching production | `New` refuses `DevUser` alongside any provider or Access; `ConfigFromEnv` refuses a stray `AUTH_DEV_USER`; a warning is logged at startup. |
| Brute force and pending-login flooding | Login, callback and logout are rate limited per client address (default 30 a minute, burst 10). |
| Secrets in logs | Client secrets have a type that prints as `[redacted]`. Tokens, codes, state and cookie values are never logged. |

### What the app must still do

- **Serve over HTTPS** on its own hostname. The cookie is scoped to the exact host.
- **Wrap every route that needs a user** in `RequireUser` or `RequireRole`. Anything not wrapped is public. Authorisation beyond roles ("is this *your* record?") is the app's.
- **Do not change state on `GET`.** The CSRF check, like `SameSite=Lax`, deliberately lets cross-site `GET` through so that links work.
- **Prevent XSS.** A script running in your page can act as the user even though it cannot read the cookie. Set a Content-Security-Policy and escape output.
- **Keep the proxy honest.** Behind a proxy, the `Host` header must reach the app unchanged. Set `AUTH_CLIENT_IP_HEADER` only if nothing but the proxy can reach the app (a NetworkPolicy, as the services have); otherwise anyone can pick their own rate-limit bucket.
- **In `access` mode, keep the Access application in place.** The package verifies tokens but Cloudflare decides who gets one. The sign-up policy still applies to people Access lets in.
- **Protect the database and its backups.** They hold email addresses and, for ten minutes at a time, PKCE verifiers.
- **Look after the client secrets** (SealedSecrets), and rotate them at the provider if they leak.
- **Decide your sign-up policy on purpose.** `open` means anyone with a Google or GitHub account can create a user.
- **Keep dependencies current.** Dependabot is set up here; bump authkit in each app after it merges.

### Known limits

- Account linking trusts each provider's claim that an address is verified. Someone who controls the mailbox, or a provider that verifies carelessly, gets the account. This is why only Google and GitHub are offered by default; think before adding an issuer with `NewOIDC`.
- The rate limiter is in memory and per process. With several replicas the limit multiplies; a restart forgets it.
- Signing out here does not sign the person out of Google or GitHub, and disabling a user takes effect on their next request, not mid-request.
- No Apple sign-in, no magic links, no multi-factor step of its own (rely on the provider's).
- Real Google and GitHub sign-ins have not been exercised by the test suite, which runs against fakes. Test both once per app after creating the OAuth clients.

## Development

```sh
task test    # fmt, vet, tests
task ci      # the PR checks: gofmt, vet, tidy, govulncheck, tests with -race
task lint    # golangci-lint
task run     # the example app in dev mode
```
