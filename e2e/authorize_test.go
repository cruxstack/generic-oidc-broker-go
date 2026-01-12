package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func TestAuthorizeEndpoint_ValidRequest(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	params := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code",
		State:        "test-state-123",
		Nonce:        "test-nonce-456",
		Scope:        "openid",
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should redirect to Twitter auth
	assert.Equal(t, http.StatusFound, resp.StatusCode)
	loc := resp.Header.Get("Location")
	assert.Contains(t, loc, "/auth/twitter")
}

func TestAuthorizeEndpoint_MissingClientID(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	params := &testutil.AuthorizeParams{
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code",
		State:        "test-state",
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error (redirect with error or direct error)
	// The behavior depends on implementation - some return 400, some redirect with error
	if resp.StatusCode == http.StatusFound {
		loc, err := testutil.GetRedirectLocation(resp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_request", loc.Query().Get("error"))
	} else {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
}

func TestAuthorizeEndpoint_InvalidClientID(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	params := &testutil.AuthorizeParams{
		ClientID:     "unknown-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code",
		State:        "test-state",
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return unauthorized_client error
	if resp.StatusCode == http.StatusFound {
		loc, err := testutil.GetRedirectLocation(resp)
		require.NoError(t, err)
		assert.Equal(t, "unauthorized_client", loc.Query().Get("error"))
	} else {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
}

func TestAuthorizeEndpoint_InvalidRedirectURI(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	params := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  "https://evil.com/callback", // Not registered
		ResponseType: "code",
		State:        "test-state",
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should NOT redirect to the invalid URI - should return error directly
	assert.NotEqual(t, http.StatusFound, resp.StatusCode, "should not redirect to unregistered URI")
}

func TestAuthorizeEndpoint_MissingResponseType(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	params := &testutil.AuthorizeParams{
		ClientID:    "test-client",
		RedirectURI: ts.URL + "/callback",
		State:       "test-state",
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error
	if resp.StatusCode == http.StatusFound {
		loc, err := testutil.GetRedirectLocation(resp)
		require.NoError(t, err)
		assert.Equal(t, "invalid_request", loc.Query().Get("error"))
	} else {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
}

func TestAuthorizeEndpoint_UnsupportedResponseType(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	params := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "unsupported_type",
		State:        "test-state",
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return unsupported_response_type error
	if resp.StatusCode == http.StatusFound {
		loc, err := testutil.GetRedirectLocation(resp)
		require.NoError(t, err)
		assert.Equal(t, "unsupported_response_type", loc.Query().Get("error"))
	} else {
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	}
}

func TestAuthorizeEndpoint_StatePreserved(t *testing.T) {
	ts := getTestServer(t)
	client := testutil.NewTestClient(ts.URL)

	expectedState := "my-unique-state-value-12345"
	params := &testutil.AuthorizeParams{
		ClientID:     "test-client",
		RedirectURI:  ts.URL + "/callback",
		ResponseType: "code",
		State:        expectedState,
	}

	resp, err := client.Client.Get(params.BuildAuthorizeURL(ts.URL))
	require.NoError(t, err)
	defer resp.Body.Close()

	// The state should be preserved through the flow
	// For now, just verify we get a redirect
	assert.Equal(t, http.StatusFound, resp.StatusCode)
}
