package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
)

func TestCodeFlow(t *testing.T) {
	s := testutil.NewServer(t)

	tests := []struct {
		provider string
		user     string
		want     map[string]any
	}{
		{"twitter", "1001", map[string]any{
			"sub": "twitter:1001", "name": "Alice Demo", "preferred_username": "alice_demo",
			"picture": "https://example.com/avatars/alice.png",
		}},
		{"github", "1002", map[string]any{
			"sub": "github:1002", "name": "Bob Tester", "preferred_username": "bob_test",
			"picture": "https://example.com/avatars/bob.png", "email": "bob@example.com", "email_verified": true,
		}},
		{"google", "1001", map[string]any{
			"sub": "google:1001", "name": "Alice Demo",
			"picture": "https://example.com/avatars/alice.png", "email": "alice@example.com", "email_verified": true,
		}},
		{"github", "1003", map[string]any{
			"sub": "github:1003", "name": "Charlie Dev", "preferred_username": "charlie_dev",
			"picture": "https://example.com/avatars/charlie.png", "email": "charlie@example.com", "email_verified": false,
		}},
		{"twitter-raw", "1001", map[string]any{
			"sub": "1001", "name": "Alice Demo", "preferred_username": "alice_demo",
			"picture": "https://example.com/avatars/alice.png",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.provider+"/"+tt.user, func(t *testing.T) {
			redirect := testutil.NewBrowser(t).Login(s, tt.provider, s.AuthParams(), tt.user)

			params := redirect.Query()
			assert.Empty(t, redirect.Fragment)
			assert.Equal(t, "client-state", params.Get("state"))
			assert.Equal(t, s.Issuer(tt.provider), params.Get("iss"))
			require.NotEmpty(t, params.Get("code"))

			idToken, accessToken := s.RedeemCode(t, tt.provider, params.Get("code"))
			claims := s.VerifyIDToken(t, tt.provider, idToken)
			assert.Equal(t, "client-nonce", claims["nonce"])
			for name, value := range tt.want {
				assert.Equal(t, value, claims[name], "ID token claim %s", name)
			}

			resp := userinfo(t, s, tt.provider, accessToken)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			assert.Equal(t, tt.want, resp.claims)
		})
	}
}

// Amazon Cognito sends a 600-700 character state when it federates to the
// broker, and a user may start a second sign-in, for example in another tab,
// before finishing the first.
func TestCodeFlow_LongClientStates(t *testing.T) {
	s := testutil.NewServer(t)
	b := testutil.NewBrowser(t)

	first, second := s.AuthParams(), s.AuthParams()
	first.Set("state", strings.Repeat("a", 650))
	second.Set("state", strings.Repeat("b", 650))
	firstAuth := b.Authorize(s, "twitter", first)
	secondAuth := b.Authorize(s, "twitter", second)

	for _, tt := range []struct {
		authorize *testutil.Response
		state     string
	}{
		{secondAuth, second.Get("state")},
		{firstAuth, first.Get("state")},
	} {
		callback := b.SignIn(tt.authorize, "1001")
		require.Equal(t, http.StatusFound, callback.StatusCode, callback.Text)
		params := callback.Location().Query()
		assert.Equal(t, tt.state, params.Get("state"))

		idToken, _ := s.RedeemCode(t, "twitter", params.Get("code"))
		assert.Equal(t, "twitter:1001", s.VerifyIDToken(t, "twitter", idToken)["sub"])
	}
}

func TestImplicitFlow(t *testing.T) {
	s := testutil.NewServer(t)
	params := s.AuthParams()
	params.Set("response_type", "id_token")

	redirect := testutil.NewBrowser(t).Login(s, "google", params, "1001")

	assert.Empty(t, redirect.RawQuery, "an ID token must never be sent in the query")
	got := testutil.ResponseParams(t, redirect)
	assert.Equal(t, "client-state", got.Get("state"))
	assert.Empty(t, got.Get("code"))
	assert.Empty(t, got.Get("access_token"), "access tokens are not returned from the authorization endpoint")

	claims := s.VerifyIDToken(t, "google", got.Get("id_token"))
	assert.Equal(t, "client-nonce", claims["nonce"])
	assert.Equal(t, "google:1001", claims["sub"])
}

func TestHybridFlow(t *testing.T) {
	s := testutil.NewServer(t)
	params := s.AuthParams()
	params.Set("response_type", "code id_token")

	redirect := testutil.NewBrowser(t).Login(s, "github", params, "1001")

	got := testutil.ResponseParams(t, redirect)
	require.NotEmpty(t, got.Get("code"))
	assert.Empty(t, got.Get("access_token"), "access tokens are not returned from the authorization endpoint")

	claims := s.VerifyIDToken(t, "github", got.Get("id_token"))
	sum := sha256.Sum256([]byte(got.Get("code")))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:16]), claims["c_hash"])

	idToken, _ := s.RedeemCode(t, "github", got.Get("code"))
	assert.Equal(t, "github:1001", s.VerifyIDToken(t, "github", idToken)["sub"])
}

func TestStateWithSpecialCharactersRoundTrips(t *testing.T) {
	s := testutil.NewServer(t)
	const state = "a b&c=d/e?f#g%h+i"

	for _, responseType := range []string{"code", "id_token"} {
		params := s.AuthParams()
		params.Set("state", state)
		params.Set("response_type", responseType)

		redirect := testutil.NewBrowser(t).Login(s, "twitter", params, "1001")
		assert.Equal(t, state, testutil.ResponseParams(t, redirect).Get("state"), responseType)
	}
}

func TestConcurrentSignInsInOneBrowser(t *testing.T) {
	s := testutil.NewServer(t)
	browser := testutil.NewBrowser(t)

	first := s.AuthParams()
	first.Set("state", "first")
	second := s.AuthParams()
	second.Set("state", "second")

	firstAuthorize := browser.Authorize(s, "github", first)
	secondAuthorize := browser.Authorize(s, "google", second)

	for _, step := range []struct {
		authorize *testutil.Response
		state     string
	}{{secondAuthorize, "second"}, {firstAuthorize, "first"}} {
		callback := browser.SignIn(step.authorize, "1001")
		require.Equal(t, http.StatusFound, callback.StatusCode, callback.Text)
		query := callback.Location().Query()
		assert.Equal(t, step.state, query.Get("state"))
		assert.NotEmpty(t, query.Get("code"))
	}
}

// upstreamState starts a sign-in and returns the state the broker sent to
// the provider.
func upstreamState(t *testing.T, s *testutil.Server, browser *testutil.Browser, provider string) string {
	t.Helper()
	resp := browser.Authorize(s, provider, s.AuthParams())
	require.Equal(t, http.StatusFound, resp.StatusCode, resp.Text)
	return resp.Location().Query().Get("state")
}

func callbackURL(s *testutil.Server, provider string, params url.Values) string {
	return s.URL + "/auth/" + provider + "/callback?" + params.Encode()
}

func TestCallback_ProviderErrorIsReturnedToClient(t *testing.T) {
	s := testutil.NewServer(t)

	tests := map[string]string{
		"access_denied":  "access_denied",
		"server_error":   "server_error",
		"invalid_scope":  "server_error",
		"something_else": "server_error",
	}
	for providerErr, wantErr := range tests {
		t.Run(providerErr, func(t *testing.T) {
			browser := testutil.NewBrowser(t)
			state := upstreamState(t, s, browser, "github")

			resp := browser.Get(callbackURL(s, "github", url.Values{"error": {providerErr}, "state": {state}}))
			require.Equal(t, http.StatusFound, resp.StatusCode, resp.Text)
			query := resp.Location().Query()
			assert.Equal(t, s.URL+"/callback", resp.Location().Scheme+"://"+resp.Location().Host+resp.Location().Path)
			assert.Equal(t, wantErr, query.Get("error"))
			assert.Equal(t, "client-state", query.Get("state"))
		})
	}
}

func TestCallback_FailedCodeExchangeIsReturnedToClient(t *testing.T) {
	s := testutil.NewServer(t)
	browser := testutil.NewBrowser(t)
	state := upstreamState(t, s, browser, "twitter")

	resp := browser.Get(callbackURL(s, "twitter", url.Values{"code": {"forged"}, "state": {state}}))
	require.Equal(t, http.StatusFound, resp.StatusCode, resp.Text)
	assert.Equal(t, "server_error", resp.Location().Query().Get("error"))
}

func TestCallback_RejectsUnknownState(t *testing.T) {
	s := testutil.NewServer(t)
	browser := testutil.NewBrowser(t)
	upstreamState(t, s, browser, "github")

	for _, state := range []string{"", "unknown"} {
		resp := browser.Get(callbackURL(s, "github", url.Values{"code": {"x"}, "state": {state}}))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("Location"))
	}
}

// A sign-in started for one provider can't be completed through another, so
// an identity from one provider can never be issued under another's issuer.
func TestCallback_RejectsSignInStartedWithAnotherProvider(t *testing.T) {
	s := testutil.NewServer(t)
	browser := testutil.NewBrowser(t)
	state := upstreamState(t, s, browser, "twitter")

	resp := browser.Get(callbackURL(s, "twitter-raw", url.Values{"code": {"x"}, "state": {state}}))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Location"))
}

func TestCallback_RejectsSignInFromAnotherBrowser(t *testing.T) {
	s := testutil.NewServer(t)
	state := upstreamState(t, s, testutil.NewBrowser(t), "github")

	resp := testutil.NewBrowser(t).Get(callbackURL(s, "github", url.Values{"code": {"x"}, "state": {state}}))
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestCallback_CannotBeReplayed(t *testing.T) {
	s := testutil.NewServer(t)
	browser := testutil.NewBrowser(t)

	authorize := browser.Authorize(s, "github", s.AuthParams())
	callback := browser.SignIn(authorize, "1001")
	require.Equal(t, http.StatusFound, callback.StatusCode)

	replay := browser.Get(callback.Request.URL.String())
	assert.Equal(t, http.StatusBadRequest, replay.StatusCode)
}
