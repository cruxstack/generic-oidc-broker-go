package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func TestAuthorize_RedirectsToProvider(t *testing.T) {
	s := testutil.NewServer(t)

	tests := []struct {
		provider string
		pkce     bool
	}{
		{"twitter", true},
		{"github", false},
		{"google", true},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			resp := testutil.NewBrowser(t).Authorize(s, tt.provider, s.AuthParams())
			require.Equal(t, http.StatusFound, resp.StatusCode, resp.Text)

			loc := resp.Location()
			query := loc.Query()
			assert.Equal(t, "/"+tt.provider+"/authorize", loc.Path)
			assert.Equal(t, tt.provider+"-client", query.Get("client_id"))
			assert.Equal(t, s.URL+"/auth/"+tt.provider+"/callback", query.Get("redirect_uri"))
			assert.NotEmpty(t, query.Get("state"))
			assert.NotEqual(t, "client-state", query.Get("state"), "the client's state must not be reused upstream")
			if tt.pkce {
				assert.Equal(t, "S256", query.Get("code_challenge_method"))
				assert.NotEmpty(t, query.Get("code_challenge"))
			} else {
				assert.Empty(t, query.Get("code_challenge"))
			}
		})
	}
}

func TestAuthorize_UnknownProvider(t *testing.T) {
	s := testutil.NewServer(t)

	resp := testutil.NewBrowser(t).Get(s.URL + "/providers/unknown/authorize?" + s.AuthParams().Encode())
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Errors are never redirected until the client and redirect URI are known to
// be valid; otherwise the endpoint would be an open redirector.
func TestAuthorize_UntrustedRedirectErrorsAreNotRedirected(t *testing.T) {
	s := testutil.NewServer(t)

	const evil = "https://evil.example/callback"
	tests := map[string]func(url.Values){
		"missing client_id":       func(p url.Values) { p.Del("client_id"); p.Set("redirect_uri", evil) },
		"unknown client_id":       func(p url.Values) { p.Set("client_id", "unknown"); p.Set("redirect_uri", evil) },
		"missing redirect_uri":    func(p url.Values) { p.Del("redirect_uri") },
		"unregistered redirect":   func(p url.Values) { p.Set("redirect_uri", evil) },
		"bad response_type too":   func(p url.Values) { p.Set("redirect_uri", evil); p.Set("response_type", "bogus") },
		"extended registered URI": func(p url.Values) { p.Set("redirect_uri", s.URL+"/callback/extra") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			params := s.AuthParams()
			mutate(params)

			resp := testutil.NewBrowser(t).Authorize(s, "github", params)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Empty(t, resp.Header.Get("Location"))
		})
	}
}

func TestAuthorize_ErrorsAreRedirectedToClient(t *testing.T) {
	s := testutil.NewServer(t)

	tests := []struct {
		name      string
		mutate    func(url.Values)
		wantError string
		fragment  bool
	}{
		{"missing response_type", func(p url.Values) { p.Del("response_type") }, "unsupported_response_type", false},
		{"implicit access token", func(p url.Values) { p.Set("response_type", "id_token token") }, "unsupported_response_type", false},
		{"token", func(p url.Values) { p.Set("response_type", "token") }, "unsupported_response_type", false},
		{"missing openid scope", func(p url.Values) { p.Set("scope", "profile email") }, "invalid_scope", false},
		{"id_token without nonce", func(p url.Values) { p.Set("response_type", "id_token"); p.Del("nonce") }, "invalid_request", true},
		{"plain PKCE", func(p url.Values) {
			p.Set("code_challenge", strings.Repeat("a", 43))
			p.Set("code_challenge_method", "plain")
		}, "invalid_request", false},
		{"PKCE method without challenge", func(p url.Values) { p.Set("code_challenge_method", "S256") }, "invalid_request", false},
		{"oversized nonce", func(p url.Values) { p.Set("nonce", strings.Repeat("n", 513)) }, "invalid_request", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := s.AuthParams()
			tt.mutate(params)

			resp := testutil.NewBrowser(t).Authorize(s, "github", params)
			require.Equal(t, http.StatusFound, resp.StatusCode, resp.Text)

			loc := resp.Location()
			assert.Equal(t, s.URL+"/callback", loc.Scheme+"://"+loc.Host+loc.Path)
			assert.Equal(t, tt.fragment, loc.Fragment != "", "error must use the response mode of the response type")
			got := testutil.ResponseParams(t, loc)
			assert.Equal(t, tt.wantError, got.Get("error"))
			assert.Equal(t, "client-state", got.Get("state"))
			assert.Equal(t, s.Issuer("github"), got.Get("iss"))
		})
	}
}
