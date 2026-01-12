// Package e2e provides end-to-end tests for the OIDC broker.
//
// These tests can be run against:
// - The Go implementation (default)
// - The Node.js implementation (set E2E_SERVER_URL)
// - Any external OIDC broker
//
// Usage:
//
//	# Test Go implementation
//	go test ./e2e/...
//
//	# Test Node.js implementation
//	E2E_SERVER_URL=http://localhost:3000 go test ./e2e/...
//
//	# Test external server
//	E2E_SERVER_URL=https://oidc.example.com go test ./e2e/...
package e2e

import (
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

var (
	testServer     *testutil.TestServer
	testServerOnce sync.Once
	testServerErr  error
)

// getTestServer returns a test server instance.
// If E2E_SERVER_URL is set, returns a wrapper for the external server.
// Otherwise, starts a local Go server with mock Twitter.
func getTestServer(t *testing.T) *testutil.TestServer {
	if testutil.UseExternalServer() {
		// Use external server (e.g., Node.js implementation)
		return &testutil.TestServer{
			URL: testutil.ExternalServerURL(),
		}
	}

	// Start local Go server (once)
	testServerOnce.Do(func() {
		testServer, testServerErr = testutil.NewTestServer(&testutil.TestServerConfig{
			UseMockTwitter: true,
		})
	})

	require.NoError(t, testServerErr, "failed to start test server")
	return testServer
}

// performAuthorizationFlow performs the full OAuth authorization flow and returns the code.
func performAuthorizationFlow(t *testing.T, ts *testutil.TestServer) string {
	authorizeParams := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code",
		State:        "test-state",
		Nonce:        "test-nonce",
		Scope:        "openid",
	}

	client := testutil.NewTestClient(ts.URL)

	// Step 1: Start authorization
	resp, err := client.Client.Get(authorizeParams.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 2: Follow redirect to Twitter
	loc, err := testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 3: Twitter authorize (mock)
	loc, err = testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	resp, err = client.Client.Get(loc.String())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 4: Twitter callback
	loc, err = testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	resp, err = client.Client.Get(ts.URL + loc.RequestURI())
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 5: Get code from final redirect
	loc, err = testutil.GetRedirectLocation(resp)
	require.NoError(t, err)

	code := loc.Query().Get("code")
	require.NotEmpty(t, code, "authorization code should be present")

	return code
}

// TestMain handles setup and teardown for all tests.
func TestMain(m *testing.M) {
	code := m.Run()

	// Cleanup
	if testServer != nil {
		testServer.Close()
	}

	os.Exit(code)
}
