package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func TestDiscoveryEndpoint(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	resp, err := client.Get("/providers/twitter/.well-known/openid-configuration")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Accept both "application/json" and "application/json; charset=utf-8"
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var doc map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&doc)
	require.NoError(t, err)

	// Verify required OIDC fields
	assert.NotEmpty(t, doc["issuer"], "issuer should be present")
	assert.NotEmpty(t, doc["authorization_endpoint"], "authorization_endpoint should be present")
	assert.NotEmpty(t, doc["token_endpoint"], "token_endpoint should be present")
	assert.NotEmpty(t, doc["jwks_uri"], "jwks_uri should be present")

	// Verify issuer matches provider-scoped config
	expectedIssuer := ts.URL + "/providers/twitter"
	assert.Equal(t, expectedIssuer, doc["issuer"])

	// Verify endpoints are properly formed (provider-scoped)
	assert.Equal(t, expectedIssuer+"/authorize", doc["authorization_endpoint"])
	assert.Equal(t, expectedIssuer+"/token", doc["token_endpoint"])
	assert.Equal(t, expectedIssuer+"/userinfo", doc["userinfo_endpoint"])
	assert.Equal(t, expectedIssuer+"/.well-known/jwks.json", doc["jwks_uri"])

	// Verify supported values
	responseTypes, ok := doc["response_types_supported"].([]interface{})
	require.True(t, ok, "response_types_supported should be an array")
	assert.Contains(t, responseTypes, "code")

	subjectTypes, ok := doc["subject_types_supported"].([]interface{})
	require.True(t, ok, "subject_types_supported should be an array")
	assert.Contains(t, subjectTypes, "public")

	signingAlgs, ok := doc["id_token_signing_alg_values_supported"].([]interface{})
	require.True(t, ok, "id_token_signing_alg_values_supported should be an array")
	assert.Contains(t, signingAlgs, "RS256")

	// scopes_supported is optional per OIDC spec, so only check if present
	if scopes, ok := doc["scopes_supported"].([]interface{}); ok {
		assert.Contains(t, scopes, "openid")
	}
}

func TestJWKSEndpoint(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	resp, err := client.Get("/providers/twitter/.well-known/jwks.json")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// Accept both "application/json" and "application/json; charset=utf-8"
	assert.Contains(t, resp.Header.Get("Content-Type"), "application/json")

	var jwks map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	require.NoError(t, err)

	// Verify keys array exists
	keys, ok := jwks["keys"].([]interface{})
	require.True(t, ok, "keys should be an array")
	require.Len(t, keys, 1, "should have exactly one key")

	// Verify key structure
	key := keys[0].(map[string]interface{})
	assert.Equal(t, "RSA", key["kty"], "key type should be RSA")
	assert.Equal(t, "RS256", key["alg"], "algorithm should be RS256")
	assert.Equal(t, "sig", key["use"], "key use should be sig")
	assert.NotEmpty(t, key["kid"], "key ID should be present")
	assert.NotEmpty(t, key["n"], "modulus should be present")
	assert.NotEmpty(t, key["e"], "exponent should be present")
}
