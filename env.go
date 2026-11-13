package authkit

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ConfigFromEnv builds a Config from environment variables; pass os.Getenv.
// The caller still sets Store (and may adjust anything else) before New.
//
//	AUTH_MODE                  session, access, "access,session" or dev (required)
//	AUTH_BASE_URL              public origin, e.g. https://app.example.com (session)
//	AUTH_GOOGLE_CLIENT_ID      \ both set: offer Google
//	AUTH_GOOGLE_CLIENT_SECRET  /
//	AUTH_GITHUB_CLIENT_ID      \ both set: offer GitHub
//	AUTH_GITHUB_CLIENT_SECRET  /
//	AUTH_ACCESS_TEAM_DOMAIN    e.g. myteam.cloudflareaccess.com (access)
//	AUTH_ACCESS_AUD            the Access application's audience tag (access)
//	AUTH_DEV_USER              email of the fixed user (dev)
//	AUTH_DEV_ROLES             comma-separated roles for the dev user
//	AUTH_SIGNUP                closed (default), allowlist or open
//	AUTH_SIGNUP_ALLOW          comma-separated addresses and domains (allowlist)
//	AUTH_ADMIN_EMAILS          comma-separated addresses seeded with role "admin"
//	AUTH_SESSION_IDLE          idle timeout as a Go duration, default 720h
//	AUTH_SESSION_MAX           absolute lifetime as a Go duration, default 2160h
//	AUTH_CLIENT_IP_HEADER      e.g. CF-Connecting-IP; only behind a trusted proxy
//
// Provider credentials and Access settings outside the selected mode are
// ignored, so AUTH_MODE alone switches between Access and own login while
// both sets of secrets stay in place.
func ConfigFromEnv(getenv func(string) string) (Config, error) {
	var cfg Config
	get := func(key string) string { return strings.TrimSpace(getenv(key)) }

	modes := splitList(get("AUTH_MODE"))
	if len(modes) == 0 {
		return cfg, errors.New("authkit: AUTH_MODE is required: session, access, access,session or dev")
	}
	for _, m := range modes {
		if m != "session" && m != "access" && m != "dev" {
			return cfg, fmt.Errorf("authkit: AUTH_MODE %q is not session, access or dev", m)
		}
	}
	if slices.Contains(modes, "dev") && len(modes) > 1 {
		return cfg, errors.New("authkit: AUTH_MODE dev cannot be combined with session or access")
	}

	cfg.BaseURL = get("AUTH_BASE_URL")
	cfg.ClientIPHeader = get("AUTH_CLIENT_IP_HEADER")

	if slices.Contains(modes, "session") {
		if id, secret := get("AUTH_GOOGLE_CLIENT_ID"), get("AUTH_GOOGLE_CLIENT_SECRET"); id != "" || secret != "" {
			p, err := Google(id, Secret(secret))
			if err != nil {
				return cfg, fmt.Errorf("authkit: AUTH_GOOGLE_CLIENT_ID and AUTH_GOOGLE_CLIENT_SECRET must both be set")
			}
			cfg.Providers = append(cfg.Providers, p)
		}
		if id, secret := get("AUTH_GITHUB_CLIENT_ID"), get("AUTH_GITHUB_CLIENT_SECRET"); id != "" || secret != "" {
			p, err := NewGitHub(GitHubConfig{ClientID: id, ClientSecret: Secret(secret)})
			if err != nil {
				return cfg, fmt.Errorf("authkit: AUTH_GITHUB_CLIENT_ID and AUTH_GITHUB_CLIENT_SECRET must both be set")
			}
			cfg.Providers = append(cfg.Providers, p)
		}
		if len(cfg.Providers) == 0 {
			return cfg, errors.New("authkit: AUTH_MODE session needs Google or GitHub credentials (AUTH_GOOGLE_* or AUTH_GITHUB_*)")
		}
		if cfg.BaseURL == "" {
			return cfg, errors.New("authkit: AUTH_MODE session needs AUTH_BASE_URL")
		}
	}
	if slices.Contains(modes, "access") {
		cfg.Access = &AccessConfig{TeamDomain: get("AUTH_ACCESS_TEAM_DOMAIN"), Audience: get("AUTH_ACCESS_AUD")}
		if cfg.Access.TeamDomain == "" || cfg.Access.Audience == "" {
			return cfg, errors.New("authkit: AUTH_MODE access needs AUTH_ACCESS_TEAM_DOMAIN and AUTH_ACCESS_AUD")
		}
	}
	if slices.Contains(modes, "dev") {
		if get("AUTH_DEV_USER") == "" {
			return cfg, errors.New("authkit: AUTH_MODE dev needs AUTH_DEV_USER")
		}
		cfg.DevUser = &DevUser{Email: get("AUTH_DEV_USER"), Name: "Dev User", Roles: splitList(get("AUTH_DEV_ROLES"))}
	} else if get("AUTH_DEV_USER") != "" {
		return cfg, errors.New("authkit: AUTH_DEV_USER is set but AUTH_MODE is not dev; unset it")
	}

	switch mode := get("AUTH_SIGNUP"); mode {
	case "", "closed":
		cfg.SignUp.Mode = SignUpClosed
	case "allowlist":
		cfg.SignUp = SignUp{Mode: SignUpAllowList, Allow: splitList(get("AUTH_SIGNUP_ALLOW"))}
	case "open":
		cfg.SignUp.Mode = SignUpOpen
	default:
		return cfg, fmt.Errorf("authkit: AUTH_SIGNUP %q is not closed, allowlist or open", mode)
	}
	for _, email := range splitList(get("AUTH_ADMIN_EMAILS")) {
		if cfg.SeedRoles == nil {
			cfg.SeedRoles = map[string][]string{}
		}
		cfg.SeedRoles[email] = []string{"admin"}
	}

	var err error
	if cfg.SessionIdleTTL, err = envDuration(get, "AUTH_SESSION_IDLE"); err != nil {
		return cfg, err
	}
	if cfg.SessionAbsoluteTTL, err = envDuration(get, "AUTH_SESSION_MAX"); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func envDuration(get func(string) string, key string) (time.Duration, error) {
	v := get(key)
	if v == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("authkit: %s %q is not a positive duration such as 720h", key, v)
	}
	return d, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
