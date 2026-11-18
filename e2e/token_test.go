package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

// newCode signs in at provider and returns a fresh authorization code.
func newCode(t *testing.T, s *testutil.Server, provider string, params url.Values) string {
	t.Helper()
	code := testutil.NewBrowser(t).Login(s, provider, params, "1001").Query().Get("code")
	require.NotEmpty(t, code)
	return code
}

func TestToken_Response(t *testing.T) {
	s := testutil.NewServer(t)
	code := newCode(t, s, "github", s.AuthParams())

	resp, body := s.RequestToken(t, "github", s.TokenForm(code))
	require.Equal(t, http.StatusOK, resp.StatusCode, body)
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	assert.Equal(t, "Bearer", body["token_type"])
	assert.Equal(t, float64(3600), body["expires_in"])
	assert.Equal(t, "openid profile email", body["scope"])
	assert.NotEmpty(t, body["access_token"])
	s.VerifyIDToken(t, "github", body["id_token"].(string))
}

func TestToken_ScopeIsNormalized(t *testing.T) {
	s := testutil.NewServer(t)
	params := s.AuthParams()
	params.Set("scope", "email openid admin openid")

	_, body := s.RequestToken(t, "github", s.TokenForm(newCode(t, s, "github", params)))
	assert.Equal(t, "email openid", body["scope"])
}

func TestToken_ClientSecretBasic(t *testing.T) {
	s := testutil.NewServer(t)

	for name, creds := range map[string][2]string{
		"raw":             {testutil.ClientID, testutil.ClientSecret},
		"form-urlencoded": {url.QueryEscape(testutil.ClientID), url.QueryEscape(testutil.ClientSecret)},
	} {
		t.Run(name, func(t *testing.T) {
			form := s.TokenForm(newCode(t, s, "github", s.AuthParams()))
			form.Del("client_id")
			form.Del("client_secret")

			req, err := http.NewRequest(http.MethodPost, s.Issuer("github")+"/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(creds[0], creds[1])
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}

func TestToken_ClientAuthenticationErrors(t *testing.T) {
	s := testutil.NewServer(t)

	tests := []struct {
		name       string
		mutate     func(url.Values)
		basic      bool
		wantStatus int
		wantError  string
	}{
		{"wrong secret", func(f url.Values) { f.Set("client_secret", "wrong") }, false, http.StatusUnauthorized, "invalid_client"},
		{"unknown client", func(f url.Values) { f.Set("client_id", "unknown") }, false, http.StatusUnauthorized, "invalid_client"},
		{"no credentials", func(f url.Values) { f.Del("client_id"); f.Del("client_secret") }, false, http.StatusUnauthorized, "invalid_client"},
		{"empty secret", func(f url.Values) { f.Set("client_secret", "") }, false, http.StatusUnauthorized, "invalid_client"},
		{"wrong basic secret", func(f url.Values) { f.Del("client_id"); f.Del("client_secret") }, true, http.StatusUnauthorized, "invalid_client"},
		{"basic and post", func(url.Values) {}, true, http.StatusBadRequest, "invalid_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := s.TokenForm("unused")
			tt.mutate(form)

			req, err := http.NewRequest(http.MethodPost, s.Issuer("github")+"/token", strings.NewReader(form.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basic {
				req.SetBasicAuth(testutil.ClientID, "wrong")
			}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			resp.Body.Close()

			assert.Equal(t, tt.wantStatus, resp.StatusCode)
			if tt.basic && tt.wantStatus == http.StatusUnauthorized {
				assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")
			}
		})
	}
}

func TestToken_ClientSecretInQueryIsIgnored(t *testing.T) {
	s := testutil.NewServer(t)
	form := s.TokenForm(newCode(t, s, "github", s.AuthParams()))
	form.Del("client_secret")

	query := url.Values{"client_secret": {testutil.ClientSecret}}
	resp, err := http.PostForm(s.Issuer("github")+"/token?"+query.Encode(), form)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestToken_RequestErrors(t *testing.T) {
	s := testutil.NewServer(t)

	tests := []struct {
		name      string
		provider  string
		mutate    func(url.Values)
		wantError string
	}{
		{"missing grant_type", "github", func(f url.Values) { f.Del("grant_type") }, "invalid_request"},
		{"unsupported grant_type", "github", func(f url.Values) { f.Set("grant_type", "password") }, "unsupported_grant_type"},
		{"missing code", "github", func(f url.Values) { f.Del("code") }, "invalid_request"},
		{"missing redirect_uri", "github", func(f url.Values) { f.Del("redirect_uri") }, "invalid_request"},
		{"unknown code", "github", func(f url.Values) { f.Set("code", "unknown") }, "invalid_grant"},
		{"redirect_uri mismatch", "github", func(f url.Values) { f.Set("redirect_uri", s.URL+"/debug/callback") }, "invalid_grant"},
		{"code from another provider", "google", func(url.Values) {}, "invalid_grant"},
		{"unexpected code_verifier", "github", func(f url.Values) { f.Set("code_verifier", oauth2.GenerateVerifier()) }, "invalid_grant"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := s.TokenForm(newCode(t, s, "github", s.AuthParams()))
			tt.mutate(form)

			resp, body := s.RequestToken(t, tt.provider, form)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, tt.wantError, body["error"])
		})
	}
}

func TestToken_CodeIsSingleUse(t *testing.T) {
	s := testutil.NewServer(t)
	form := s.TokenForm(newCode(t, s, "github", s.AuthParams()))

	first, _ := s.RequestToken(t, "github", form)
	require.Equal(t, http.StatusOK, first.StatusCode)

	second, body := s.RequestToken(t, "github", form)
	assert.Equal(t, http.StatusBadRequest, second.StatusCode)
	assert.Equal(t, "invalid_grant", body["error"])
}

func TestToken_PKCE(t *testing.T) {
	s := testutil.NewServer(t)
	verifier := oauth2.GenerateVerifier()
	params := s.AuthParams()
	params.Set("code_challenge", oauth2.S256ChallengeFromVerifier(verifier))
	params.Set("code_challenge_method", "S256")

	tests := map[string]struct {
		verifier   string
		wantStatus int
	}{
		"correct verifier": {verifier, http.StatusOK},
		"missing verifier": {"", http.StatusBadRequest},
		"wrong verifier":   {oauth2.GenerateVerifier(), http.StatusBadRequest},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			form := s.TokenForm(newCode(t, s, "github", params))
			if tt.verifier != "" {
				form.Set("code_verifier", tt.verifier)
			}
			resp, body := s.RequestToken(t, "github", form)
			assert.Equal(t, tt.wantStatus, resp.StatusCode, body)
		})
	}
}

func TestToken_RepeatedAuthenticationFailuresAreThrottled(t *testing.T) {
	s := testutil.NewServer(t)
	bad := s.TokenForm("unused")
	bad.Set("client_secret", "wrong")

	for range 10 {
		resp, _ := s.RequestToken(t, "github", bad)
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	}

	resp, body := s.RequestToken(t, "github", s.TokenForm(newCode(t, s, "github", s.AuthParams())))
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode, body)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}
