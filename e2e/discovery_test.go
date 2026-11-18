// Package e2e tests the broker end to end: the production router from
// internal/app, driven like a browser and an OIDC client, against the mock
// provider.
package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func getJSON(t *testing.T, url string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Get(url)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	}
	return resp, body
}

func TestDiscovery(t *testing.T) {
	s := testutil.NewServer(t)

	for _, provider := range []string{"twitter", "github", "google"} {
		t.Run(provider, func(t *testing.T) {
			issuer := s.Issuer(provider)
			resp, doc := getJSON(t, issuer+"/.well-known/openid-configuration")
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, "application/json", resp.Header.Get("Content-Type"))

			assert.Equal(t, issuer, doc["issuer"])
			assert.Equal(t, issuer+"/authorize", doc["authorization_endpoint"])
			assert.Equal(t, issuer+"/token", doc["token_endpoint"])
			assert.Equal(t, issuer+"/userinfo", doc["userinfo_endpoint"])
			assert.Equal(t, issuer+"/.well-known/jwks.json", doc["jwks_uri"])
			assert.ElementsMatch(t, []any{"code", "id_token", "code id_token"}, doc["response_types_supported"])
			assert.Equal(t, []any{"S256"}, doc["code_challenge_methods_supported"])
			assert.Equal(t, []any{"RS256"}, doc["id_token_signing_alg_values_supported"])
			assert.Equal(t, true, doc["authorization_response_iss_parameter_supported"])
		})
	}
}

func TestDiscovery_UnknownProvider(t *testing.T) {
	s := testutil.NewServer(t)

	resp, _ := getJSON(t, s.URL+"/providers/unknown/.well-known/openid-configuration")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestJWKS(t *testing.T) {
	s := testutil.NewServer(t)

	resp, jwks := getJSON(t, s.Issuer("github")+"/.well-known/jwks.json")
	require.Equal(t, http.StatusOK, resp.StatusCode)

	keys := jwks["keys"].([]any)
	require.Len(t, keys, 1)
	key := keys[0].(map[string]any)
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "RS256", key["alg"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, "test-key", key["kid"])
	assert.NotContains(t, key, "d", "the private exponent must never be published")
}

func TestHealth(t *testing.T) {
	s := testutil.NewServer(t)

	resp := testutil.NewBrowser(t).Get(s.URL + "/health")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", resp.Text)
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
}
