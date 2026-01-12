package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func TestUserinfoEndpoint_ValidToken(t *testing.T) {
	ts := getTestServer(t)

	// Get tokens through the full flow
	code := performAuthorizationFlow(t, ts)
	accessToken := exchangeCodeForToken(t, ts, code)

	// Call userinfo endpoint
	client := testutil.NewTestClient(ts.URL)
	resp, err := client.GetWithAuth("/providers/twitter/userinfo", accessToken)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var userinfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userinfo)
	require.NoError(t, err)

	// Verify required claims
	assert.NotEmpty(t, userinfo["sub"], "sub claim should be present")
}

func TestUserinfoEndpoint_MissingToken(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	resp, err := client.Get("/providers/twitter/userinfo")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Should have WWW-Authenticate header
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
}

func TestUserinfoEndpoint_InvalidToken(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	resp, err := client.GetWithAuth("/providers/twitter/userinfo", "invalid-token-12345")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	// Should have WWW-Authenticate header with error
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, "invalid_token")
}

func TestUserinfoEndpoint_MalformedAuthHeader(t *testing.T) {
	ts := getTestServer(t)

	// Create a custom request with malformed auth header
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/providers/twitter/userinfo", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "NotBearer token123")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// exchangeCodeForToken exchanges an authorization code for an access token.
func exchangeCodeForToken(t *testing.T, ts *testutil.TestServer, code string) string {
	client := testutil.NewTestClient(ts.URL)
	tokenParams := &testutil.TokenParams{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  ts.URL + "/callback",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	resp, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	return tokenResp["access_token"].(string)
}
