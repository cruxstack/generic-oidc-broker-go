package e2e

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func TestTokenEndpoint_ValidRequest(t *testing.T) {
	ts := getTestServer(t)

	// First, get an authorization code through the full flow
	code := performAuthorizationFlow(t, ts)

	// Exchange code for tokens
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

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	// Verify token response
	assert.NotEmpty(t, tokenResp["access_token"], "access_token should be present")
	assert.NotEmpty(t, tokenResp["id_token"], "id_token should be present")
	assert.Equal(t, "Bearer", tokenResp["token_type"])
	assert.NotZero(t, tokenResp["expires_in"])

	// Verify ID token is a valid JWT
	idToken := tokenResp["id_token"].(string)
	parts := strings.Split(idToken, ".")
	assert.Len(t, parts, 3, "ID token should be a valid JWT with 3 parts")

	// Decode and verify claims
	claims := decodeJWTClaims(t, idToken)
	assert.Equal(t, ts.URL+"/providers/twitter", claims["iss"], "issuer should match provider-scoped issuer")
	assert.NotEmpty(t, claims["sub"], "subject should be present")
	assert.NotEmpty(t, claims["aud"], "audience should be present")
	assert.NotEmpty(t, claims["exp"], "expiration should be present")
	assert.NotEmpty(t, claims["iat"], "issued at should be present")
}

func TestTokenEndpoint_BasicAuth(t *testing.T) {
	ts := getTestServer(t)
	code := performAuthorizationFlow(t, ts)

	client := testutil.NewTestClient(ts.URL)
	data := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	}

	resp, err := client.PostFormWithBasicAuth("/providers/twitter/token", data, "test-client", "test-secret")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var tokenResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	require.NoError(t, err)

	assert.NotEmpty(t, tokenResp["access_token"])
	assert.NotEmpty(t, tokenResp["id_token"])
}

func TestTokenEndpoint_InvalidCode(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	tokenParams := &testutil.TokenParams{
		GrantType:    "authorization_code",
		Code:         "invalid-code-12345",
		RedirectURI:  ts.URL + "/callback",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	resp, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errorResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	require.NoError(t, err)

	assert.Equal(t, "invalid_grant", errorResp["error"])
}

func TestTokenEndpoint_InvalidClientCredentials(t *testing.T) {
	ts := getTestServer(t)
	code := performAuthorizationFlow(t, ts)

	client := testutil.NewTestClient(ts.URL)
	tokenParams := &testutil.TokenParams{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  ts.URL + "/callback",
		ClientID:     "test-client",
		ClientSecret: "wrong-secret",
	}

	resp, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	var errorResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	require.NoError(t, err)

	assert.Equal(t, "invalid_client", errorResp["error"])
}

func TestTokenEndpoint_MissingCode(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	tokenParams := &testutil.TokenParams{
		GrantType:    "authorization_code",
		RedirectURI:  ts.URL + "/callback",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	resp, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errorResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	require.NoError(t, err)

	assert.Equal(t, "invalid_request", errorResp["error"])
}

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	tokenParams := &testutil.TokenParams{
		GrantType:    "password", // Not supported
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	resp, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

	var errorResp map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&errorResp)
	require.NoError(t, err)

	assert.Equal(t, "unsupported_grant_type", errorResp["error"])
}

func TestTokenEndpoint_CodeReuse(t *testing.T) {
	ts := getTestServer(t)
	code := performAuthorizationFlow(t, ts)

	client := testutil.NewTestClient(ts.URL)
	tokenParams := &testutil.TokenParams{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  ts.URL + "/callback",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}

	// First exchange should succeed
	resp1, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	resp1.Body.Close()
	assert.Equal(t, http.StatusOK, resp1.StatusCode)

	// Second exchange should fail (code is single-use)
	resp2, err := client.PostForm("/providers/twitter/token", tokenParams.ToFormValues())
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusBadRequest, resp2.StatusCode)

	var errorResp map[string]interface{}
	err = json.NewDecoder(resp2.Body).Decode(&errorResp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_grant", errorResp["error"])
}

// decodeJWTClaims decodes the claims from a JWT without verifying the signature.
func decodeJWTClaims(t *testing.T, token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "JWT should have 3 parts")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]interface{}
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)

	return claims
}
