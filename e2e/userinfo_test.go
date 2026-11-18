package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

type userinfoResponse struct {
	*http.Response
	claims map[string]any
}

// userinfo calls a provider's userinfo endpoint with a bearer token.
func userinfo(t *testing.T, s *testutil.Server, provider, bearer string) userinfoResponse {
	t.Helper()
	return userinfoWithMethod(t, s, provider, http.MethodGet, bearer)
}

func userinfoWithMethod(t *testing.T, s *testutil.Server, provider, method, bearer string) userinfoResponse {
	t.Helper()
	req, err := http.NewRequest(method, s.Issuer(provider)+"/userinfo", nil)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	result := userinfoResponse{Response: resp}
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&result.claims))
	}
	return result
}

// signIn returns tokens for user 1001 at provider.
func signIn(t *testing.T, s *testutil.Server, provider string) (idToken, accessToken string) {
	t.Helper()
	return s.RedeemCode(t, provider, newCode(t, s, provider, s.AuthParams()))
}

func TestUserinfo_GETAndPOST(t *testing.T) {
	s := testutil.NewServer(t)
	_, accessToken := signIn(t, s, "google")

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		resp := userinfoWithMethod(t, s, "google", method, accessToken)
		require.Equal(t, http.StatusOK, resp.StatusCode, method)
		assert.Equal(t, "google:1001", resp.claims["sub"])
		assert.Equal(t, "alice@example.com", resp.claims["email"])
		assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))
	}
}

func TestUserinfo_WithoutToken(t *testing.T) {
	s := testutil.NewServer(t)

	resp := userinfo(t, s, "github", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Equal(t, `Bearer realm="oidc-broker"`, resp.Header.Get("WWW-Authenticate"))
}

func TestUserinfo_RejectsInvalidTokens(t *testing.T) {
	s := testutil.NewServer(t)
	idToken, accessToken := signIn(t, s, "github")

	tests := map[string]struct{ provider, token string }{
		"garbage":                    {"github", "not-a-jwt"},
		"ID token":                   {"github", idToken},
		"tampered signature":         {"github", accessToken[:len(accessToken)-4] + "AAAA"},
		"token for google issuer":    {"google", accessToken},
		"token for twitter issuer":   {"twitter", accessToken},
		"token for unprefixed alias": {"twitter-raw", accessToken},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			resp := userinfo(t, s, tt.provider, tt.token)
			assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
			assert.Contains(t, resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`)
		})
	}
}

func TestUserinfo_RateLimited(t *testing.T) {
	s := testutil.NewServer(t)

	for i := range 100 {
		resp := userinfo(t, s, "github", "invalid")
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "request %d", i+1)
	}
	resp := userinfo(t, s, "github", "invalid")
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
}
