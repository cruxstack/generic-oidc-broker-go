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
	// GoogleDefaultAuthURL is Google's OAuth 2.0 authorization endpoint.
	GoogleDefaultAuthURL = "https://accounts.google.com/o/oauth2/v2/auth"
	// GoogleDefaultTokenURL is Google's OAuth 2.0 token endpoint.
	GoogleDefaultTokenURL = "https://oauth2.googleapis.com/token"
	// GoogleDefaultUserURL is Google's user info endpoint.
	GoogleDefaultUserURL = "https://www.googleapis.com/oauth2/v2/userinfo"
)

// GoogleProvider implements the Provider interface for Google OAuth 2.0.
type GoogleProvider struct {
	config Config
}

// NewGoogleProvider creates a new Google provider.
func NewGoogleProvider(cfg Config) (*GoogleProvider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("google: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("google: client_secret is required")
	}
	if cfg.CallbackURL == "" {
		return nil, fmt.Errorf("google: callback_url is required")
	}

	// Set defaults
	if cfg.AuthURL == "" {
		cfg.AuthURL = GoogleDefaultAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = GoogleDefaultTokenURL
	}
	if cfg.UserURL == "" {
		cfg.UserURL = GoogleDefaultUserURL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "profile", "email"}
	}

	return &GoogleProvider{config: cfg}, nil
}

// GoogleProviderFactory creates a Google provider from config.
func GoogleProviderFactory(cfg Config) (Provider, error) {
	return NewGoogleProvider(cfg)
}

// Name returns the provider identifier (the configured name, not the type).
func (p *GoogleProvider) Name() string {
	return p.config.Name
}

// AuthURL returns the full authorization URL.
func (p *GoogleProvider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.config.ClientID},
		"redirect_uri":          {p.config.CallbackURL},
		"scope":                 {strings.Join(p.config.Scopes, " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"access_type":           {"offline"}, // Request refresh token
	}
	return p.config.AuthURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.config.CallbackURL},
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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

// googleUserResponse represents Google's user info response structure.
type googleUserResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
}

// GetUser fetches user information from Google.
func (p *GoogleProvider) GetUser(ctx context.Context, accessToken string) (*UserData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.UserURL, nil)
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

	var userResp googleUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	return &UserData{
		ID:              userResp.ID,
		Provider:        p.config.Name,
		Name:            userResp.Name,
		Email:           userResp.Email,
		EmailVerified:   userResp.VerifiedEmail,
		ProfileImageURL: userResp.Picture,
	}, nil
}

// Scopes returns the OAuth scopes.
func (p *GoogleProvider) Scopes() []string {
	return p.config.Scopes
}

// SupportsPKCE returns true as Google supports PKCE.
func (p *GoogleProvider) SupportsPKCE() bool {
	return true
}

// PrefixSubject returns whether the subject should be prefixed with provider name.
func (p *GoogleProvider) PrefixSubject() bool {
	return p.config.PrefixSubject
}
