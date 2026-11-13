package authkit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
)

// GitHubConfig configures the GitHub provider.
type GitHubConfig struct {
	ClientID     string
	ClientSecret Secret
	// WebURL and APIURL default to https://github.com and
	// https://api.github.com. Tests point them at a fake; GitHub Enterprise
	// Server would use https://HOST and https://HOST/api/v3.
	WebURL string
	APIURL string
	// HTTPClient defaults to a client with a 10 second timeout.
	HTTPClient *http.Client
}

// GitHub is the Provider for github.com accounts, named "github". GitHub's
// web login is plain OAuth 2, not OpenID Connect, so there is no ID token:
// the account id and verified primary email come from two API calls.
type GitHub struct {
	cfg GitHubConfig
}

// NewGitHub returns the GitHub provider.
func NewGitHub(cfg GitHubConfig) (*GitHub, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("authkit: GitHub provider needs ClientID and ClientSecret")
	}
	if cfg.WebURL == "" {
		cfg.WebURL = "https://github.com"
	}
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	cfg.WebURL, cfg.APIURL = strings.TrimRight(cfg.WebURL, "/"), strings.TrimRight(cfg.APIURL, "/")
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = defaultHTTPClient()
	}
	return &GitHub{cfg: cfg}, nil
}

// Name implements Provider.
func (*GitHub) Name() string { return "github" }

// Label implements Provider.
func (*GitHub) Label() string { return "GitHub" }

func (g *GitHub) oauth(redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.cfg.ClientID,
		ClientSecret: g.cfg.ClientSecret.Reveal(),
		Endpoint: oauth2.Endpoint{
			AuthURL:   g.cfg.WebURL + "/login/oauth/authorize",
			TokenURL:  g.cfg.WebURL + "/login/oauth/access_token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"read:user", "user:email"},
	}
}

// AuthCodeURL implements Provider.
func (g *GitHub) AuthCodeURL(_ context.Context, a AuthParams) (string, error) {
	return g.oauth(a.RedirectURL).AuthCodeURL(a.State, oauth2.S256ChallengeOption(a.Verifier)), nil
}

// Exchange implements Provider.
func (g *GitHub) Exchange(ctx context.Context, a AuthParams, code string) (Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.cfg.HTTPClient)
	conf := g.oauth(a.RedirectURL)
	tok, err := conf.Exchange(ctx, code, oauth2.VerifierOption(a.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("authkit: github code exchange: %w", err)
	}
	client := conf.Client(ctx, tok)

	var user struct {
		Login string `json:"login"`
		Name  string `json:"name"`
		ID    int64  `json:"id"`
	}
	if err := g.get(ctx, client, "/user", &user); err != nil {
		return Identity{}, err
	}
	if user.ID == 0 {
		return Identity{}, errors.New("authkit: github user has no id")
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.get(ctx, client, "/user/emails?per_page=100", &emails); err != nil {
		return Identity{}, err
	}
	name := user.Name
	if name == "" {
		name = user.Login
	}
	for _, e := range emails {
		if e.Primary && e.Verified && e.Email != "" {
			return Identity{
				Provider: g.Name(), Subject: strconv.FormatInt(user.ID, 10),
				Email: e.Email, EmailVerified: true, Name: name,
			}, nil
		}
	}
	return Identity{}, ErrEmailNotVerified
}

func (g *GitHub) get(ctx context.Context, client *http.Client, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.APIURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("authkit: github %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authkit: github %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(into); err != nil {
		return fmt.Errorf("authkit: github %s: %w", path, err)
	}
	return nil
}
