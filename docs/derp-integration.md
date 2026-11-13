# Adopting authkit in derp: plan

Status: a plan, not yet carried out. Written November 2026 against authkit as first built and derp as described in `services/derp/docs/multi-user.md` (called "the investigation" below). To be executed in a later session, in the `services` repo.

## Summary

- derp becomes multi-user first, still behind Cloudflare Access. That is the investigation's step 1 and most of the work. authkit supplies the "who is this request?" part of it.
- An `AUTH_MODE` setting then moves derp from Access to its own login without another code change: `access` → `access,session` → `session`.
- `/admin` stays behind a Cloudflare Access application throughout, as well as needing the `admin` role in the app.
- Every step up to the Cloudflare change can be undone by setting `AUTH_MODE` back. Users are matched by verified email in every mode, so nobody's progress moves.
- The riskiest unknown is the redirect to Google or GitHub and back inside the installed iOS app. Test it in stage 3, before anyone depends on it.

## Before starting

1. **Check authkit has a release.** `github.com/relloyd/authkit` is public and its release workflow tags `main` on merge; the first release is `v0.1.0`. Use the latest tag. derp's Docker build runs `go mod download` with the service directory as its context, so the module must be fetchable from the proxy; a public repo needs no `GOPRIVATE` or credentials in the Dockerfile or CI.
2. **Back up derp's database** (`task backup` in `derp/`). Stage 1's migration cannot be undone except by restoring.
3. **Answer the investigation's open questions** that affect this plan: invite-only or open sign-up (`AUTH_SIGNUP`), and whether the hourly backup sidecar goes in before other people's history is on the Pi.

## Stage 1: multi-user, behind Access (`AUTH_MODE=access`)

This is the investigation's "What multi-user changes in the app", with one change of shape: authkit owns the account, derp owns what is specific to the quiz.

### Schema

authkit's `sqlitestore` creates its own tables (`authkit_users`, `authkit_identities`, `authkit_user_roles`, `authkit_sessions`, `authkit_pending_logins`) in derp's database file and tracks its own version in `authkit_schema`. derp's `PRAGMA user_version` is untouched.

derp's migration `002` therefore does **not** create the `users` table the investigation sketched. Instead:

| Investigation's `users` column | Where it lives now |
|---|---|
| id, email, display name, disabled, created | `authkit_users` |
| role (`player` or `admin`) | `authkit_user_roles`; "player" is simply having no `admin` role |
| timezone, reminder opt-in, last seen, reminder marker | new derp table `players (user_id INTEGER PRIMARY KEY, tz_name, reminder_opt_in, last_seen_at, reminder_sent_day)` |

Migration `002` also adds `user_id INTEGER NOT NULL DEFAULT 1` to `progress`, `attempts` and `days` and rebuilds their keys as the investigation describes (user and challenge; user and day).

Existing rows belong to user 1, so user 1 must be the owner. Startup order in `cmd/derp`:

1. Open the database.
2. `sqlitestore.New(ctx, db)`: creates the authkit tables.
3. If `authkit_users` is empty, `store.CreateUser(ctx, OWNER_EMAIL, "", []string{"admin"})`. In an empty table this is id 1. Refuse to start if `OWNER_EMAIL` is unset at this point.
4. Run derp's own migrations, including `002`.

Add a store test that starts from a copy of a version-1 database with history and checks the streak and XP are unchanged for user 1 afterwards.

### Code

- `internal/config`: read auth settings with `authkit.ConfigFromEnv(os.Getenv)`; add `OWNER_EMAIL`. Set `cfg.APIPrefixes = []string{"/api/", "/admin/api/"}` and `cfg.LoginPath = "/"` (derp is a single page; see stage 2).
- `internal/api/router.go`: `auth.Register(mux)`; wrap the `/api/v1/` handlers in `auth.RequireUser`; read the user with `authkit.UserFrom(r.Context())` and pass `user.ID` down. Leave `/healthz` and `/readyz` unwrapped (the kubelet probes them). The static files stay public: they hold no user data, and the login screen must load signed out.
- `internal/store`, `internal/game`: every method takes a user id (mechanical, as the investigation says).
- The state response gains `user: {name, email, roles}` so the UI can show who is signed in and link to admin.
- Tests: use `AUTH_MODE=dev` wiring, or `authkit.WithUser` to place a user in the request context for handler tests.

### Configuration

ConfigMap (`deploy/base/configmap.yaml`, patched in the `pi` overlay):

```yaml
AUTH_MODE: "access"
AUTH_ACCESS_TEAM_DOMAIN: "<team>.cloudflareaccess.com"
AUTH_ACCESS_AUD: "<audience tag of the derp Access application>"
AUTH_SIGNUP: "closed"                    # Access already decides who gets in; widen when inviting people
AUTH_CLIENT_IP_HEADER: "CF-Connecting-IP" # safe: the NetworkPolicy admits only cloudflared
```

Email addresses are personal data and the repo's ConfigMaps are plain text, so `OWNER_EMAIL` and `AUTH_ADMIN_EMAILS` go in the `derp-secrets` SealedSecret beside `MAIL_TO`, not in the ConfigMap.

Local development: `task run` sets `AUTH_MODE=dev`, `AUTH_DEV_USER` and `AUTH_DEV_ROLES=admin` (replacing the investigation's `DEV_USER`). authkit refuses to start if a dev user is configured alongside Access or providers.

### What this stage closes

Today derp trusts that everything reaching it came through Access. After this stage it verifies the Access token on every request and fails closed if the Access application is ever removed or misconfigured.

### Check before moving on

- Your history, streak and XP are intact; `/auth/me` shows your address and `admin`.
- A second address allowed in the Access policy (and in `AUTH_SIGNUP_ALLOW`, or with `AUTH_SIGNUP=open`) gets an empty account of its own.
- `kubectl port-forward` straight to the pod, bypassing Cloudflare: `/api/v1/state` answers 401.

## Stage 2: login screen and logout in the front end

Built now, visible only once `session` is on. All in `internal/api/static/app/`.

- **Detect signed out.** The `fetch` wrapper in `app.js` treats a 401 as "show the login screen" instead of an error. On start the app calls `/api/v1/state` as it does now; a 401 leads to the login screen.
- **Login screen.** Fetch `/auth/providers` and render one button per entry: "Continue with Google", "Continue with GitHub". Each is a plain link (`<a href="/auth/login/google">`), a full-page navigation in the same window. Do not use `fetch`, `window.open` or `target="_blank"`: the flow depends on cookies set in this browsing context (see the iOS section). When the list is empty (Access-only mode) show nothing; Access has already signed the person in.
- **Errors.** authkit sends a failed login back to `LoginPath` with `?error=<code>`. With `LoginPath` set to `/`, the app reads `error` from the query string on start, shows a sentence for it (copy the wording from authkit's `example/main.go`), and removes it from the address bar with `history.replaceState`.
- **Logout.** A "Sign out" entry in the existing menu. In `session` mode: `fetch('/auth/logout', {method: 'POST'})`, then show the login screen. In `access` mode the session belongs to Cloudflare: link to `/cdn-cgi/access/logout`. The app can tell which applies from whether `/auth/providers` returned any.
- **Who is signed in.** Show the name or address from the state response beside the sign-out entry, and an "Admin" link when `roles` includes `admin`.
- **Content-Security-Policy.** The buttons navigate to the same origin, which then redirects, so `default-src 'self'` needs no change. Check `form-action` and `navigate-to` if derp sets either.
- `ghost.js` is unaffected. Add vitest cases only if logic (rather than rendering) is added.

## Stage 3: cutover (`AUTH_MODE=access,session`)

Both authenticators are accepted. The hostname is still wholly behind Access, so nothing is exposed yet; this stage exists to prove the login works in production, on the phone, before Access is removed.

### OAuth clients

Create them as the authkit README describes, with these callback URLs:

- Google: `https://derp.tubetimeout.com/auth/callback/google`
- GitHub: `https://derp.tubetimeout.com/auth/callback/github`

The GitHub OAuth app is for this hostname only; another app on another hostname needs its own. For local testing create a second GitHub OAuth app with `http://localhost:8080/auth/callback/github`, and add the localhost URI to the same Google client.

### SealedSecret entries

Add to `derp-secrets` (values from 1Password through `sealed-secrets/secrets.yaml`, then `task sealed-secrets:seal SECRET=derp-secrets`):

| Key | Note |
|---|---|
| `AUTH_GOOGLE_CLIENT_ID` | not secret, kept beside its secret for convenience |
| `AUTH_GOOGLE_CLIENT_SECRET` | secret |
| `AUTH_GITHUB_CLIENT_ID` | not secret |
| `AUTH_GITHUB_CLIENT_SECRET` | secret |
| `OWNER_EMAIL` | from stage 1 |
| `AUTH_ADMIN_EMAILS` | from stage 1 |

There is no session key to generate: sessions are random ids stored (hashed) in the database.

ConfigMap changes:

```yaml
AUTH_MODE: "access,session"
AUTH_BASE_URL: "https://derp.tubetimeout.com"   # same value as PUBLIC_URL
AUTH_SIGNUP: "allowlist"                        # or "open"; with Access gone this is the only gate
AUTH_SIGNUP_ALLOW: "example.org"                # if allowlist; put personal addresses in the SealedSecret instead
```

`task validate-manifests` at the repo root must still pass (it rejects plain Secrets).

### Check before moving on

With Access still in front, the app shows no login screen by itself (Access has already identified you). Exercise the flow by opening `https://derp.tubetimeout.com/auth/login/google` and then `/auth/login/github` directly:

- Each returns to the app, and `/auth/me` shows the **same user id** as before. The `authkit_identities` table now has rows for `cloudflare-access`, `google` and `github`, all for user 1.
- An address outside the sign-up policy lands back on the app with the "not open to that address" message.
- Run the iOS checks below.

## Stage 4: remove Access from the app, keep it on `/admin`

Do this at a quiet time; it is the step that exposes the app to the internet.

In Cloudflare Zero Trust, **Access > Applications**:

1. **Add a new application** for the admin area first: self-hosted, hostname `derp.tubetimeout.com`, path `admin`. Policy: Allow, your address only. Session length as you prefer. Note its audience tag.
2. **Remove the hostname-wide application** for `derp.tubetimeout.com` (or change its only policy to Bypass, which is easier to reverse). More specific paths win, so `/admin` stays protected.
3. Check from a private window, signed out of everything: the app loads and shows the login screen; `https://derp.tubetimeout.com/admin` shows Cloudflare's login.

Then set:

```yaml
AUTH_MODE: "access,session"                 # keep both; see below
AUTH_ACCESS_AUD: "<audience tag of the new /admin application>"
```

Why keep `access` on: requests to `/admin` now carry a token from the new application. With its audience tag configured, derp accepts either a session or that token for `/admin`, and requires the `admin` role in both cases. Tokens from the old hostname-wide application stop being accepted because the tag has changed. Setting `AUTH_MODE=session` instead is also valid; `/admin` is then protected by Cloudflare at the edge and by the role check on the session, and derp ignores the Access header.

Either way the two protections on `/admin` are the investigation's: an Access policy for your address, and `role = admin` in the app (`auth.RequireRole("admin")` on `/admin/` and `/admin/api/`). Note what is and is not enforced in the app: derp checks the role itself, but it relies on Cloudflare and the NetworkPolicy for the guarantee that an `/admin` request passed Access. That is deliberate: a `kubectl port-forward` straight to the pod stays available as a backup route for debugging (see decisions).

The tunnel's ingress rules in `cloudflare/deploy/overlays/pi/configmap-data.yaml` do not change; only its comment ("protected by Cloudflare Access; the app has no login of its own") needs updating.

### After the cutover

- derp is now directly reachable. authkit rate limits its own endpoints; `/api/v1/answer` and `/api/v1/session` are derp's to limit, as the investigation notes.
- Watch the logs for `authkit:` warnings for a few days: rejected callbacks and refused sign-ups are logged without secrets.
- The 50-seat Access limit no longer applies to players; only you use a seat, for `/admin`.

## Rollback

| Stage | To undo |
|---|---|
| 4 (Access removed) | In Cloudflare, restore the hostname-wide application (or switch its policy from Bypass back to Allow). **Do this first.** Then set `AUTH_ACCESS_AUD` back to its audience tag. The app is private again at once; sessions people already hold keep working behind Access. |
| 3 (`access,session`) | Set `AUTH_MODE: "access"` and redeploy. Provider credentials can stay sealed; they are ignored outside `session`. Session rows left in the database are harmless and expire. |
| 2 (front end) | Nothing to undo: with no providers on offer the login screen never shows. |
| 1 (multi-user) | Not reversible in place. Restore the pre-migration backup and deploy the previous image. Anything played since is lost, which is why stage 1 should settle for a few days before stage 3. |

In every mode a person is the same user, found by verified email, so moving between modes in either direction does not disturb progress. One caveat: someone who signed up through Google or GitHub after stage 4 with an address that is not in the Access policy cannot get in after a rollback to Access until the policy admits them.

## Testing the redirect flow in the installed iOS PWA

derp is installed to the home screen and runs standalone (`"display": "standalone"` in the manifest). This is the part of the change most likely to behave differently from desktop, and it has not been tested; treat what follows as a checklist, not a description of known behaviour.

The concern: an installed web app on iOS keeps its own cookies, separate from Safari's. When the app navigates to `accounts.google.com` or `github.com`, which are outside the app's scope, iOS may show that page in an in-app browser sheet or hand it to Safari, depending on the iOS version. The login only completes if the callback to `derp.tubetimeout.com/auth/callback/...` arrives **in the same cookie store that started it**, because authkit checks a state cookie set at the start, and because the session cookie must end up inside the installed app. If the start and the callback happen in different stores, the visible symptom is the app (or Safari) landing on `/?error=invalid_state`, or Safari ending up signed in while the installed app is not.

Test on the actual phone, in stage 3, with the app installed from the home screen:

1. **Fresh install.** Remove the home-screen app, add it again, open it. Tap "Continue with Google".
   - Does the provider page open inside the app, in a sheet over it, or in Safari?
   - After approving, do you land back **in the installed app**, signed in?
2. **GitHub**, the same. GitHub may offer to open its own app if installed; try with and without it.
3. **Already signed in to the provider in Safari.** Is the provider's session recognised from inside the app, or does it ask for a password again? (Expect to be asked again; that is acceptable.)
4. **Persistence.** Close the app from the app switcher, reopen: still signed in? Restart the phone: still signed in? Leave it a week: still signed in? (Session lifetime is 30 days idle, 90 absolute; iOS may clear storage for sites unused for a while, though installed apps are treated more leniently.)
5. **Cancel.** Start a login and dismiss the provider page. The app should be usable, showing the login screen.
6. **Sign out** from the menu, then sign in with the other provider: same account, same streak.
7. **Safari tab** (not installed): the same flow in ordinary Safari, as the baseline.
8. **Passkeys and two-step prompts** at the provider complete inside whatever view iOS used.

If the callback lands in the wrong place:

- Confirm the buttons are plain same-window links, with no `target` and no `window.open`.
- Check the manifest `scope` and `start_url` cover `/auth/` (they do if scope is `/`).
- As a fallback, show a short "Finish signing in" page at the end of the callback that the installed app can pick up, or keep installed-app users on Access for longer. Either is a design change to discuss, not something to improvise during the cutover.

Record the iOS version and the outcome of each step in this file when done.

## Decisions (November 2026)

- **No Access check inside the app for `/admin`.** authkit accepts an Access token *or* a session, and has no middleware that demands both on one request. Richard chose to leave it that way for now, so that `kubectl port-forward` to the pod remains a backup route when debugging. The cost: if the `/admin` Access application is ever deleted or misconfigured, derp will not notice and `/admin` is protected by the session's `admin` role alone. A `RequireAccess` middleware in authkit would close that and can be added later.
- **Accounts in `authkit_users`, quiz settings in a derp `players` table**, instead of the single `users` table the investigation sketched. The table name and exact columns are still open.

## Open questions

- **Sign-up policy at cutover:** allow-list or open? With Access gone it is the only gate.
- **Privacy note and delete-my-account** (the investigation's data-protection section) should exist before stage 4, since that is when strangers can sign up. `sqlitestore.DeleteUser` removes the account; derp must delete its own rows for the user first.
- **Other services:** delayrepay and tt-relay's admin are also behind Access. Nothing here changes them; each would repeat stages 1 to 4 with its own GitHub OAuth app.
