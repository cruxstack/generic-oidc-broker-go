package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// GitHubDefaultAuthURL is GitHub's OAuth 2.0 authorization endpoint.
	GitHubDefaultAuthURL = "https://github.com/login/oauth/authorize"
	// GitHubDefaultTokenURL is GitHub's OAuth 2.0 token endpoint.
	GitHubDefaultTokenURL = "https://github.com/login/oauth/access_token"
	// GitHubDefaultUserURL is GitHub's user info endpoint.
	GitHubDefaultUserURL = "https://api.github.com/user"
)

// GitHubProvider implements the Provider interface for GitHub OAuth 2.0.
type GitHubProvider struct {
	config Config
}

// NewGitHubProvider creates a new GitHub provider.
func NewGitHubProvider(cfg Config) (*GitHubProvider, error) {
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("github: client_id is required")
	}
	if cfg.ClientSecret == "" {
		return nil, fmt.Errorf("github: client_secret is required")
	}
	if cfg.CallbackURL == "" {
		return nil, fmt.Errorf("github: callback_url is required")
	}

	// Set defaults
	if cfg.AuthURL == "" {
		cfg.AuthURL = GitHubDefaultAuthURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = GitHubDefaultTokenURL
	}
	if cfg.UserURL == "" {
		cfg.UserURL = GitHubDefaultUserURL
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"read:user", "user:email"}
	}

	return &GitHubProvider{config: cfg}, nil
}

// GitHubProviderFactory creates a GitHub provider from config.
func GitHubProviderFactory(cfg Config) (Provider, error) {
	return NewGitHubProvider(cfg)
}

// Name returns the provider identifier (the configured name, not the type).
func (p *GitHubProvider) Name() string {
	return p.config.Name
}

// AuthURL returns the full authorization URL.
// Note: GitHub does not support PKCE, so codeChallenge is ignored.
func (p *GitHubProvider) AuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":    {p.config.ClientID},
		"redirect_uri": {p.config.CallbackURL},
		"scope":        {strings.Join(p.config.Scopes, " ")},
		"state":        {state},
	}
	return p.config.AuthURL + "?" + params.Encode()
}

// ExchangeCode exchanges an authorization code for tokens.
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error) {
	data := url.Values{
		"client_id":     {p.config.ClientID},
		"client_secret": {p.config.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.config.CallbackURL},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.config.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

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

	// GitHub returns a slightly different format
	var ghResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
		ErrorDesc   string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &ghResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if ghResp.Error != "" {
		return nil, fmt.Errorf("github error: %s - %s", ghResp.Error, ghResp.ErrorDesc)
	}

	return &TokenResponse{
		AccessToken: ghResp.AccessToken,
		TokenType:   ghResp.TokenType,
		Scope:       ghResp.Scope,
	}, nil
}

// githubUserResponse represents GitHub's user info response structure.
type githubUserResponse struct {
	ID        int    `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// GetUser fetches user information from GitHub.
func (p *GitHubProvider) GetUser(ctx context.Context, accessToken string) (*UserData, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.UserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

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

	var userResp githubUserResponse
	if err := json.Unmarshal(body, &userResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	userData := &UserData{
		ID:              strconv.Itoa(userResp.ID),
		Provider:        p.config.Name,
		Name:            userResp.Name,
		Username:        userResp.Login,
		Email:           userResp.Email,
		ProfileImageURL: userResp.AvatarURL,
	}

	// If email is not public, try to fetch from /user/emails endpoint
	if userData.Email == "" {
		email, verified := p.fetchPrimaryEmail(ctx, accessToken)
		userData.Email = email
		userData.EmailVerified = verified
	} else {
		// Public emails are considered verified by GitHub
		userData.EmailVerified = true
	}

	return userData, nil
}

// fetchPrimaryEmail fetches the user's primary email from GitHub.
func (p *GitHubProvider) fetchPrimaryEmail(ctx context.Context, accessToken string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return "", false
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false
	}

	// Find primary email
	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified
		}
	}

	// Fallback to first verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, true
		}
	}

	return "", false
}

// Scopes returns the OAuth scopes.
func (p *GitHubProvider) Scopes() []string {
	return p.config.Scopes
}

// SupportsPKCE returns false as GitHub does not support PKCE.
func (p *GitHubProvider) SupportsPKCE() bool {
	return false
}

// PrefixSubject returns whether the subject should be prefixed with provider name.
func (p *GitHubProvider) PrefixSubject() bool {
	return p.config.PrefixSubject
}
