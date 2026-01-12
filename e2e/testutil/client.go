package testutil

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

// TestClient is an HTTP client for testing the OIDC broker.
type TestClient struct {
	*http.Client
	BaseURL string
}

// NewTestClient creates a new test client.
func NewTestClient(baseURL string) *TestClient {
	jar, _ := cookiejar.New(nil)
	return &TestClient{
		Client: &http.Client{
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Don't follow redirects automatically - we want to inspect them
				return http.ErrUseLastResponse
			},
		},
		BaseURL: baseURL,
	}
}

// NewTestClientFollowRedirects creates a test client that follows redirects.
func NewTestClientFollowRedirects(baseURL string) *TestClient {
	jar, _ := cookiejar.New(nil)
	return &TestClient{
		Client: &http.Client{
			Jar: jar,
		},
		BaseURL: baseURL,
	}
}

// Get performs a GET request.
func (c *TestClient) Get(path string) (*http.Response, error) {
	return c.Client.Get(c.BaseURL + path)
}

// GetWithParams performs a GET request with query parameters.
func (c *TestClient) GetWithParams(path string, params url.Values) (*http.Response, error) {
	u := c.BaseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	return c.Client.Get(u)
}

// PostForm performs a POST request with form data.
func (c *TestClient) PostForm(path string, data url.Values) (*http.Response, error) {
	return c.Client.PostForm(c.BaseURL+path, data)
}

// PostFormWithBasicAuth performs a POST request with form data and basic auth.
func (c *TestClient) PostFormWithBasicAuth(path string, data url.Values, username, password string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+path, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(username, password)
	return c.Client.Do(req)
}

// GetWithAuth performs a GET request with a Bearer token.
func (c *TestClient) GetWithAuth(path, token string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.Client.Do(req)
}

// ReadJSON reads the response body as JSON into the given value.
func ReadJSON(resp *http.Response, v interface{}) error {
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}

// ReadBody reads the response body as a string.
func ReadBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// GetRedirectLocation extracts the Location header from a redirect response.
func GetRedirectLocation(resp *http.Response) (*url.URL, error) {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return nil, fmt.Errorf("expected redirect, got status %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, fmt.Errorf("no Location header in redirect response")
	}
	return url.Parse(loc)
}

// ExtractCodeFromRedirect extracts the authorization code from a redirect URL.
func ExtractCodeFromRedirect(resp *http.Response) (string, error) {
	loc, err := GetRedirectLocation(resp)
	if err != nil {
		return "", err
	}
	code := loc.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("no code in redirect URL: %s", loc.String())
	}
	return code, nil
}

// ExtractErrorFromRedirect extracts error information from a redirect URL.
func ExtractErrorFromRedirect(resp *http.Response) (errorCode, errorDesc string, err error) {
	loc, err := GetRedirectLocation(resp)
	if err != nil {
		return "", "", err
	}
	return loc.Query().Get("error"), loc.Query().Get("error_description"), nil
}

// AuthorizeParams holds parameters for the authorize endpoint.
type AuthorizeParams struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Nonce        string
	Scope        string
	Provider     string // Provider name for provider-scoped endpoint
}

// BuildAuthorizeURL builds an authorization URL with the given parameters.
func (p *AuthorizeParams) BuildAuthorizeURL(baseURL string) string {
	params := url.Values{}
	if p.ClientID != "" {
		params.Set("client_id", p.ClientID)
	}
	if p.RedirectURI != "" {
		params.Set("redirect_uri", p.RedirectURI)
	}
	if p.ResponseType != "" {
		params.Set("response_type", p.ResponseType)
	}
	if p.State != "" {
		params.Set("state", p.State)
	}
	if p.Nonce != "" {
		params.Set("nonce", p.Nonce)
	}
	if p.Scope != "" {
		params.Set("scope", p.Scope)
	}

	// Use provider-scoped endpoint
	provider := p.Provider
	if provider == "" {
		provider = "twitter" // default provider for tests
	}
	return baseURL + "/providers/" + provider + "/authorize?" + params.Encode()
}

// TokenParams holds parameters for the token endpoint.
type TokenParams struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
}

// ToFormValues converts the parameters to form values.
func (p *TokenParams) ToFormValues() url.Values {
	data := url.Values{}
	if p.GrantType != "" {
		data.Set("grant_type", p.GrantType)
	}
	if p.Code != "" {
		data.Set("code", p.Code)
	}
	if p.RedirectURI != "" {
		data.Set("redirect_uri", p.RedirectURI)
	}
	if p.ClientID != "" {
		data.Set("client_id", p.ClientID)
	}
	if p.ClientSecret != "" {
		data.Set("client_secret", p.ClientSecret)
	}
	return data
}
