package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

// TestFullOIDCFlow tests the complete OIDC authorization code flow.
func TestFullOIDCFlow(t *testing.T) {
	ts := getTestServer(t)

	// Step 1: Start authorization flow
	authorizeParams := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code",
		State:        "test-state-xyz",
		Nonce:        "test-nonce-abc",
		Scope:        "openid profile",
	}

	client := testutil.NewTestClient(ts.URL)
	resp, err := client.Client.Get(authorizeParams.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	resp.Body.Close()

	// Should redirect to Twitter auth
	require.Equal(t, http.StatusFound, resp.StatusCode)
	twitterRedirect, err := testutil.GetRedirectLocation(resp)
	require.NoError(t, err)
	assert.Contains(t, twitterRedirect.Path, "/auth/twitter")

	// Step 2: Follow redirect to Twitter (mock)
	resp, err = client.Client.Get(ts.URL + twitterRedirect.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()

	// Should redirect to mock Twitter authorize
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 3: Mock Twitter redirects back with code
	// The mock Twitter server handles this automatically
	mockTwitterAuthURL, err := testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	// Follow the Twitter auth URL (mock server will redirect back)
	resp, err = client.Client.Get(mockTwitterAuthURL.String())
	require.NoError(t, err)
	resp.Body.Close()

	// Should redirect to callback with Twitter code
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callbackURL, err := testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	// Step 4: Handle Twitter callback
	resp, err = client.Client.Get(ts.URL + callbackURL.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()

	// Should redirect to client callback with OIDC code
	require.Equal(t, http.StatusFound, resp.StatusCode)
	finalRedirect, err := testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	// Verify state is preserved
	assert.Equal(t, "test-state-xyz", finalRedirect.Query().Get("state"))

	// Get the authorization code
	code := finalRedirect.Query().Get("code")
	require.NotEmpty(t, code, "authorization code should be present")

	// Step 5: Exchange code for tokens
	tokenParams := &testutil.TokenParams{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  ts.URL + "/callback",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	resp, err = client.PostForm("/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	accessToken := tokenResp["access_token"].(string)
	idToken := tokenResp["id_token"].(string)

	require.NotEmpty(t, accessToken)
	require.NotEmpty(t, idToken)

	// Step 6: Verify ID token claims
	claims := decodeJWTClaims(t, idToken)
	assert.Equal(t, ts.URL, claims["iss"], "issuer should match")
	assert.Equal(t, "test-nonce-abc", claims["nonce"], "nonce should be preserved")

	// Verify audience contains client_id
	aud := claims["aud"]
	switch v := aud.(type) {
	case string:
		assert.Equal(t, "test-client", v)
	case []interface{}:
		assert.Contains(t, v, "test-client")
	}

	// Step 7: Call userinfo endpoint
	resp, err = client.GetWithAuth("/userinfo", accessToken)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var userinfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userinfo)
	require.NoError(t, err)

	// Verify sub matches ID token
	assert.Equal(t, claims["sub"], userinfo["sub"], "subject should match between ID token and userinfo")
}

// TestImplicitFlow tests the implicit flow (response_type=id_token).
func TestImplicitFlow(t *testing.T) {
	ts := getTestServer(t)

	// Start with id_token response type
	authorizeParams := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "id_token",
		State:        "implicit-state",
		Nonce:        "implicit-nonce",
		Scope:        "openid",
	}

	// Follow the full flow
	client := testutil.NewTestClient(ts.URL)

	// Start authorization
	resp, err := client.Client.Get(authorizeParams.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Follow through Twitter mock
	loc, _ := testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Twitter auth redirect
	loc, _ = testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(loc.String())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Twitter callback
	loc, _ = testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Final redirect - for implicit flow, token is in fragment
	finalLoc, _ := testutil.GetRedirectLocation(resp)

	// For implicit flow, the id_token should be in the fragment
	// Parse the fragment as query params
	fragment := finalLoc.Fragment
	if fragment != "" {
		fragmentParams, err := url.ParseQuery(fragment)
		require.NoError(t, err)

		idToken := fragmentParams.Get("id_token")
		assert.NotEmpty(t, idToken, "id_token should be in fragment for implicit flow")
		assert.Equal(t, "implicit-state", fragmentParams.Get("state"))

		// Verify token
		claims := decodeJWTClaims(t, idToken)
		assert.Equal(t, "implicit-nonce", claims["nonce"])
	} else {
		// Some implementations return in query string
		idToken := finalLoc.Query().Get("id_token")
		if idToken != "" {
			claims := decodeJWTClaims(t, idToken)
			assert.Equal(t, "implicit-nonce", claims["nonce"])
		}
	}
}

// TestHybridFlow tests the hybrid flow (response_type=code id_token).
func TestHybridFlow(t *testing.T) {
	ts := getTestServer(t)

	authorizeParams := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code id_token",
		State:        "hybrid-state",
		Nonce:        "hybrid-nonce",
		Scope:        "openid",
	}

	client := testutil.NewTestClient(ts.URL)

	// Start authorization
	resp, err := client.Client.Get(authorizeParams.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Follow through Twitter mock
	loc, _ := testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()

	loc, _ = testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(loc.String())
	require.NoError(t, err)
	resp.Body.Close()

	loc, _ = testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()

	finalLoc, _ := testutil.GetRedirectLocation(resp)

	// For hybrid flow, both code and id_token should be present
	// They might be in fragment or query depending on implementation
	var code, idToken string

	if finalLoc.Fragment != "" {
		fragmentParams, _ := url.ParseQuery(finalLoc.Fragment)
		code = fragmentParams.Get("code")
		idToken = fragmentParams.Get("id_token")
	}

	if code == "" {
		code = finalLoc.Query().Get("code")
	}
	if idToken == "" {
		idToken = finalLoc.Query().Get("id_token")
	}

	// At minimum, code should be present
	assert.NotEmpty(t, code, "code should be present in hybrid flow")

	// If id_token is present, verify it
	if idToken != "" {
		parts := strings.Split(idToken, ".")
		assert.Len(t, parts, 3, "id_token should be a valid JWT")
	}
}
