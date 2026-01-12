package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

// TestProviderScopedDiscoveryEndpoint tests the provider-specific discovery endpoint.
func TestProviderScopedDiscoveryEndpoint(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	resp, err := client.Get("/providers/twitter/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var doc map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&doc)
	require.NoError(t, err)

	// Verify issuer is provider-scoped
	expectedIssuer := ts.URL + "/providers/twitter"
	assert.Equal(t, expectedIssuer, doc["issuer"], "issuer should be provider-scoped")

	// Verify endpoints are properly formed with provider prefix
	assert.Equal(t, expectedIssuer+"/authorize", doc["authorization_endpoint"])
	assert.Equal(t, expectedIssuer+"/token", doc["token_endpoint"])
	assert.Equal(t, expectedIssuer+"/userinfo", doc["userinfo_endpoint"])

	// JWKS URI is provider-scoped (same key, but provider-specific path)
	assert.Equal(t, expectedIssuer+"/.well-known/jwks.json", doc["jwks_uri"])
}

// TestProviderScopedDiscoveryEndpointNotFound tests the discovery endpoint for an unknown provider.
func TestProviderScopedDiscoveryEndpointNotFound(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	resp, err := client.Get("/providers/unknown/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// TestProviderScopedFullOIDCFlow tests the complete OIDC authorization code flow using provider-scoped endpoints.
func TestProviderScopedFullOIDCFlow(t *testing.T) {
	ts := getTestServer(t)

	// Step 1: Start authorization flow via provider-scoped endpoint
	authorizeParams := url.Values{}
	authorizeParams.Set("client_id", "test-client")
	authorizeParams.Set("redirect_uri", ts.URL+"/callback")
	authorizeParams.Set("response_type", "code")
	authorizeParams.Set("state", "provider-scoped-state")
	authorizeParams.Set("nonce", "provider-scoped-nonce")
	authorizeParams.Set("scope", "openid profile")

	client := testutil.NewTestClient(ts.URL)
	authorizeURL := ts.URL + "/providers/twitter/authorize?" + authorizeParams.Encode()

	resp, err := client.Client.Get(authorizeURL)
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
	mockTwitterAuthURL, err := testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

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
	assert.Equal(t, "provider-scoped-state", finalRedirect.Query().Get("state"))

	// Get the authorization code
	code := finalRedirect.Query().Get("code")
	require.NotEmpty(t, code, "authorization code should be present")

	// Step 5: Exchange code for tokens via provider-scoped token endpoint
	tokenParams := url.Values{}
	tokenParams.Set("grant_type", "authorization_code")
	tokenParams.Set("code", code)
	tokenParams.Set("redirect_uri", ts.URL+"/callback")
	tokenParams.Set("client_id", "test-client")
	tokenParams.Set("client_secret", "test-secret")

	resp, err = client.PostForm("/providers/twitter/token", tokenParams)
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

	// Step 6: Verify ID token has provider-scoped issuer
	claims := decodeJWTClaims(t, idToken)
	expectedIssuer := ts.URL + "/providers/twitter"
	assert.Equal(t, expectedIssuer, claims["iss"], "issuer should be provider-scoped")
	assert.Equal(t, "provider-scoped-nonce", claims["nonce"], "nonce should be preserved")

	// Verify audience contains client_id
	aud := claims["aud"]
	switch v := aud.(type) {
	case string:
		assert.Equal(t, "test-client", v)
	case []interface{}:
		assert.Contains(t, v, "test-client")
	}

	// Step 7: Call provider-scoped userinfo endpoint
	resp, err = client.GetWithAuth("/providers/twitter/userinfo", accessToken)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var userinfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userinfo)
	require.NoError(t, err)

	// Verify sub matches ID token
	assert.Equal(t, claims["sub"], userinfo["sub"], "subject should match between ID token and userinfo")
}

// TestProviderScopedTokenEndpointIssuerMismatch tests that token endpoint rejects codes from different issuers.
func TestProviderScopedTokenEndpointIssuerMismatch(t *testing.T) {
	ts := getTestServer(t)

	// Get a code via root authorize endpoint (no provider scope)
	code := performAuthorizationFlow(t, ts)
	require.NotEmpty(t, code)

	client := testutil.NewTestClient(ts.URL)

	// Try to exchange code via provider-scoped token endpoint (should fail - issuer mismatch)
	tokenParams := url.Values{}
	tokenParams.Set("grant_type", "authorization_code")
	tokenParams.Set("code", code)
	tokenParams.Set("redirect_uri", ts.URL+"/callback")
	tokenParams.Set("client_id", "test-client")
	tokenParams.Set("client_secret", "test-secret")

	resp, err := client.PostForm("/providers/twitter/token", tokenParams)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail with 400 Bad Request (issuer mismatch)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errResp)
	require.NoError(t, err)

	assert.Equal(t, "invalid_grant", errResp["error"])
}

// TestProviderScopedUserinfoEndpointIssuerMismatch tests that userinfo endpoint rejects tokens from different issuers.
func TestProviderScopedUserinfoEndpointIssuerMismatch(t *testing.T) {
	ts := getTestServer(t)

	// Get tokens via root endpoints (no provider scope)
	code := performAuthorizationFlow(t, ts)
	require.NotEmpty(t, code)

	client := testutil.NewTestClient(ts.URL)

	// Exchange code for tokens via root token endpoint
	tokenParams := url.Values{}
	tokenParams.Set("grant_type", "authorization_code")
	tokenParams.Set("code", code)
	tokenParams.Set("redirect_uri", ts.URL+"/callback")
	tokenParams.Set("client_id", "test-client")
	tokenParams.Set("client_secret", "test-secret")

	resp, err := client.PostForm("/token", tokenParams)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)
	resp.Body.Close()

	accessToken := tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Verify root token has root issuer
	claims := decodeJWTClaims(t, accessToken)
	assert.Equal(t, ts.URL, claims["iss"], "root token should have root issuer")

	// Try to call provider-scoped userinfo endpoint with root token (should fail)
	resp, err = client.GetWithAuth("/providers/twitter/userinfo", accessToken)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail with 401 Unauthorized (issuer mismatch)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// TestRootTokenAtRootUserinfo verifies root tokens work at root userinfo endpoint.
func TestRootTokenAtRootUserinfo(t *testing.T) {
	ts := getTestServer(t)

	code := performAuthorizationFlow(t, ts)
	require.NotEmpty(t, code)

	client := testutil.NewTestClient(ts.URL)

	// Exchange code for tokens via root token endpoint
	tokenParams := url.Values{}
	tokenParams.Set("grant_type", "authorization_code")
	tokenParams.Set("code", code)
	tokenParams.Set("redirect_uri", ts.URL+"/callback")
	tokenParams.Set("client_id", "test-client")
	tokenParams.Set("client_secret", "test-secret")

	resp, err := client.PostForm("/token", tokenParams)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)
	resp.Body.Close()

	accessToken := tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Root token should work at root userinfo endpoint
	resp, err = client.GetWithAuth("/userinfo", accessToken)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var userinfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userinfo)
	require.NoError(t, err)
	assert.NotEmpty(t, userinfo["sub"])
}

// TestProviderScopedTokenAtProviderUserinfo verifies provider-scoped tokens work at provider-scoped userinfo.
func TestProviderScopedTokenAtProviderUserinfo(t *testing.T) {
	ts := getTestServer(t)

	// Get code via provider-scoped authorize
	authorizeParams := url.Values{}
	authorizeParams.Set("client_id", "test-client")
	authorizeParams.Set("redirect_uri", ts.URL+"/callback")
	authorizeParams.Set("response_type", "code")
	authorizeParams.Set("state", "test-state")
	authorizeParams.Set("nonce", "test-nonce")
	authorizeParams.Set("scope", "openid")

	client := testutil.NewTestClient(ts.URL)
	authorizeURL := ts.URL + "/providers/twitter/authorize?" + authorizeParams.Encode()

	// Follow the full flow
	resp, err := client.Client.Get(authorizeURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, _ := testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, _ = testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(loc.String())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	loc, _ = testutil.GetRedirectLocation(resp)
	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	finalLoc, _ := testutil.GetRedirectLocation(resp)
	code := finalLoc.Query().Get("code")
	require.NotEmpty(t, code)

	// Exchange code via provider-scoped token endpoint
	tokenParams := url.Values{}
	tokenParams.Set("grant_type", "authorization_code")
	tokenParams.Set("code", code)
	tokenParams.Set("redirect_uri", ts.URL+"/callback")
	tokenParams.Set("client_id", "test-client")
	tokenParams.Set("client_secret", "test-secret")

	resp, err = client.PostForm("/providers/twitter/token", tokenParams)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)
	resp.Body.Close()

	accessToken := tokenResp["access_token"].(string)
	require.NotEmpty(t, accessToken)

	// Verify token has provider-scoped issuer
	claims := decodeJWTClaims(t, accessToken)
	expectedIssuer := ts.URL + "/providers/twitter"
	assert.Equal(t, expectedIssuer, claims["iss"])

	// Provider-scoped token should work at provider-scoped userinfo
	resp, err = client.GetWithAuth("/providers/twitter/userinfo", accessToken)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var userinfo map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&userinfo)
	require.NoError(t, err)
	assert.NotEmpty(t, userinfo["sub"])
}
