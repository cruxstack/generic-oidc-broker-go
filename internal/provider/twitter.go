package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	// TwitterDefaultAuthURL is Twitter's OAuth 2.0 authorization endpoint.
	TwitterDefaultAuthURL = "https://twitter.com/i/oauth2/authorize"
	// TwitterDefaultTokenURL is Twitter's OAuth 2.0 token endpoint.
	TwitterDefaultTokenURL = "https://api.x.com/2/oauth2/token"
	// TwitterDefaultUserURL is Twitter's user info endpoint.
	TwitterDefaultUserURL = "https://api.x.com/2/users/me"
)

// TwitterProvider implements the Provider interface for Twitter OAuth 2.0.
type TwitterProvider struct {
	config Config
}

// NewTwitterProvider creates a new Twitter provider.
func NewTwitterProvider(cfg Config) (*TwitterProvider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("twitter: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("twitter: client_secret is required")
	}
	if cfg.CallbackURL == "" {
		return nil, fmt.Errorf("twitter: callback_url is required")
	}

	// Set defaults
	if cfg.AuthURL == "" {
		cfg.AuthURL = TwitterDefaultAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = TwitterDefaultTokenURL
	}
	if cfg.UserURL == "" {
		cfg.UserURL = TwitterDefaultUserURL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"tweet.read", "users.read", "offline.access"}
	}

	return &TwitterProvider{config: cfg}, nil
}

// TwitterProviderFactory creates a Twitter provider from config.
func TwitterProviderFactory(cfg Config) (Provider, error) {
	return NewTwitterProvider(cfg)
}

// Name returns the provider identifier (the configured name, not the type).
func (p *TwitterProvider) Name() string {
	return p.config.Name
}

// AuthURL returns the full authorization URL.
func (p *TwitterProvider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.config.ClientID},
		"redirect_uri":          {p.config.CallbackURL},
		"scope":                 {strings.Join(p.config.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return p.config.AuthURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *TwitterProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.config.CallbackURL},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.config.ClientID, p.config.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &tokenResp, nil
}

// twitterUserResponse represents Twitter's user info response structure.
type twitterUserResponse struct {
	Data struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Username        string `json:"username"`
		ProfileImageURL string `json:"profile_image_url"`
	} `json:"data"`
}

// GetUser fetches user information from Twitter.
func (p *TwitterProvider) GetUser(ctx context.Context, accessToken string) (*UserData, error) {
	userURL := p.config.UserURL + "?user.fields=profile_image_url"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var userResp twitterUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &UserData{
		ID:              userResp.Data.ID,
		Provider:        p.config.Name,
		Name:            userResp.Data.Name,
		Username:        userResp.Data.Username,
		ProfileImageURL: userResp.Data.ProfileImageURL,
	}, nil
}

// Scopes returns the OAuth scopes.
func (p *TwitterProvider) Scopes() []string {
	return p.config.Scopes
}

// SupportsPKCE returns true as Twitter requires PKCE.
func (p *TwitterProvider) SupportsPKCE() bool {
	return true
}

// PrefixSubject returns whether the subject should be prefixed with provider name.
func (p *TwitterProvider) PrefixSubject() bool {
	return p.config.PrefixSubject
}
