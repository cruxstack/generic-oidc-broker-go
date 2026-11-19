package handler

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestParseResponseType(t *testing.T) {
	tests := map[string]struct {
		want responseType
		ok   bool
	}{
		"code":           {responseType{Code: true}, true},
		"id_token":       {responseType{IDToken: true}, true},
		"code id_token":  {responseType{Code: true, IDToken: true}, true},
		"id_token  code": {responseType{Code: true, IDToken: true}, true},
		"":               {responseType{}, false},
		"token":          {responseType{}, false},
		"id_token token": {responseType{}, false},
		"code code":      {responseType{}, false},
		"CODE":           {responseType{}, false},
	}
	for raw, tt := range tests {
		got, ok := parseResponseType(raw)
		assert.Equal(t, tt.ok, ok, raw)
		assert.Equal(t, tt.want, got, raw)
	}
}

func TestNormalizeScope(t *testing.T) {
	tests := map[string]struct {
		want   string
		openid bool
	}{
		"openid":                    {"openid", true},
		"email openid admin openid": {"email openid", true},
		"profile email":             {"profile email", false},
		"":                          {"", false},
	}
	for raw, tt := range tests {
		got, openid := normalizeScope(raw)
		assert.Equal(t, tt.want, got, raw)
		assert.Equal(t, tt.openid, openid, raw)
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := oauth2.GenerateVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)

	assert.True(t, verifyPKCE("", ""), "no PKCE")
	assert.True(t, verifyPKCE(challenge, verifier))
	assert.False(t, verifyPKCE(challenge, ""), "missing verifier")
	assert.False(t, verifyPKCE(challenge, oauth2.GenerateVerifier()), "wrong verifier")
	assert.False(t, verifyPKCE("", verifier), "verifier without challenge (downgrade)")
}

func TestIsS256Challenge(t *testing.T) {
	assert.True(t, isS256Challenge(oauth2.S256ChallengeFromVerifier("v")))
	assert.False(t, isS256Challenge(strings.Repeat("a", 42)))
	assert.False(t, isS256Challenge(strings.Repeat("+", 43)))
}

func TestReadClientCredentials(t *testing.T) {
	tests := []struct {
		name    string
		form    url.Values
		basic   []string
		want    clientCredentials
		wantErr string
	}{
		{"post", url.Values{"client_id": {"app"}, "client_secret": {"s"}}, nil, clientCredentials{id: "app", secret: "s"}, ""},
		{"basic", nil, []string{"app", "s"}, clientCredentials{id: "app", secret: "s", basic: true}, ""},
		{"basic with matching client_id", url.Values{"client_id": {"app"}}, []string{"app", "s"}, clientCredentials{id: "app", secret: "s", basic: true}, ""},
		{"basic with encoded matching client_id", url.Values{"client_id": {"my app"}}, []string{"my+app", "s"}, clientCredentials{id: "my+app", secret: "s", basic: true}, ""},
		{"both methods", url.Values{"client_secret": {"s"}}, []string{"app", "s"}, clientCredentials{}, "not both"},
		{"mismatched client_id", url.Values{"client_id": {"other"}}, []string{"app", "s"}, clientCredentials{}, "does not match"},
		{"none", nil, nil, clientCredentials{}, errNoClientAuth.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tt.basic != nil {
				req.SetBasicAuth(tt.basic[0], tt.basic[1])
			}
			require.NoError(t, req.ParseForm())

			got, err := readClientCredentials(req)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestClientErrorFor(t *testing.T) {
	assert.Equal(t, "access_denied", clientErrorFor("access_denied"))
	assert.Equal(t, "temporarily_unavailable", clientErrorFor("temporarily_unavailable"))
	assert.Equal(t, "server_error", clientErrorFor("invalid_client"))
}

// requestWithCookies returns a request carrying the cookies rec set.
func requestWithCookies(rec *httptest.ResponseRecorder) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func newTestFlowCookie(t *testing.T) (*flowCookie, *time.Time) {
	t.Helper()
	f, err := newFlowCookie(strings.Repeat("s", 32), true)
	require.NoError(t, err)
	now := time.Now()
	f.now = func() time.Time { return now }
	return f, &now
}

func TestFlowCookie_TakeIsOneTime(t *testing.T) {
	f, now := newTestFlowCookie(t)
	rec := httptest.NewRecorder()
	require.NoError(t, f.add(rec, httptest.NewRequest(http.MethodGet, "/", nil), "state-1", authorizationRequest{ClientID: "app", CreatedAt: *now}))

	cookie := rec.Result().Cookies()[0]
	assert.True(t, cookie.HttpOnly)
	assert.True(t, cookie.Secure)
	assert.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
	assert.NotContains(t, cookie.Value, "app", "the cookie is encrypted")

	takeRec := httptest.NewRecorder()
	req, ok, err := f.take(takeRec, requestWithCookies(rec), "state-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "app", req.ClientID)

	_, ok, _ = f.take(httptest.NewRecorder(), requestWithCookies(takeRec), "state-1")
	assert.False(t, ok)
}

func TestFlowCookie_KeepsTheNewestFlows(t *testing.T) {
	f, now := newTestFlowCookie(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for i := range maxPendingFlows + 1 {
		*now = now.Add(time.Second)
		state := string(rune('a' + i))
		require.NoError(t, f.add(rec, req, state, authorizationRequest{CreatedAt: *now}))
		req = requestWithCookies(rec)
		rec = httptest.NewRecorder()
	}

	flows := f.load(req)
	assert.Len(t, flows, maxPendingFlows)
	assert.NotContains(t, flows, "a", "the oldest flow is dropped")
}

// largeRequest returns an authorization request with a state of n characters
// that JSON does not escape.
func largeRequest(createdAt time.Time, n int) authorizationRequest {
	return authorizationRequest{
		Provider:         "twitter",
		ClientID:         "92db6e93-c4b0-46a3-b798-8207866e9f10",
		RedirectURI:      "https://example.auth.us-east-1.amazoncognito.com/oauth2/idpresponse",
		ResponseType:     responseType{Code: true},
		Scope:            "openid email",
		State:            strings.Repeat("s", n),
		ProviderVerifier: oauth2.GenerateVerifier(),
		CreatedAt:        createdAt,
	}
}

func TestFlowCookie_FitsTheLargestAllowedRequest(t *testing.T) {
	f, now := newTestFlowCookie(t)
	req := largeRequest(*now, maxStateLength)
	req.Nonce = strings.Repeat("n", maxNonceLength)
	req.RedirectURI += "?" + strings.Repeat("q", 200)
	req.CodeChallenge = oauth2.S256ChallengeFromVerifier("v")

	rec := httptest.NewRecorder()
	require.NoError(t, f.add(rec, httptest.NewRequest(http.MethodGet, "/", nil), rand.Text(), req))
	cookie := rec.Result().Cookies()[0]
	assert.LessOrEqual(t, len(cookie.Name)+1+len(cookie.Value), 4096)
}

// Clients such as Amazon Cognito send long state values. When several of
// their sign-ins don't fit in the cookie together, the oldest are dropped.
func TestFlowCookie_DropsOlderFlowsToFit(t *testing.T) {
	f, now := newTestFlowCookie(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	var states []string
	for range maxPendingFlows {
		*now = now.Add(time.Second)
		state := rand.Text()
		states = append(states, state)
		require.NoError(t, f.add(rec, req, state, largeRequest(*now, 900)))
		cookie := rec.Result().Cookies()[0]
		assert.LessOrEqual(t, len(cookie.Name)+1+len(cookie.Value), 4096)
		req = requestWithCookies(rec)
		rec = httptest.NewRecorder()
	}

	flows := f.load(req)
	assert.Less(t, len(flows), maxPendingFlows, "the requests are too large to all fit")
	assert.NotContains(t, flows, states[0], "the oldest flow is dropped")
	require.Contains(t, flows, states[len(states)-1], "the newest flow is kept")
	assert.Len(t, flows[states[len(states)-1]].State, 900)
}

func TestFlowCookie_RejectsRequestsThatCannotFit(t *testing.T) {
	f, now := newTestFlowCookie(t)
	rec := httptest.NewRecorder()
	require.NoError(t, f.add(rec, httptest.NewRequest(http.MethodGet, "/", nil), "kept", authorizationRequest{CreatedAt: *now}))

	// JSON escapes "&" as &, so this state alone overflows the cookie.
	huge := largeRequest(*now, 0)
	huge.State = strings.Repeat("&", maxStateLength)
	tooLargeRec := httptest.NewRecorder()
	err := f.add(tooLargeRec, requestWithCookies(rec), "huge", huge)
	require.ErrorIs(t, err, errFlowTooLarge)
	assert.Empty(t, tooLargeRec.Result().Cookies(), "the existing cookie is left as is")
}

func TestFlowCookie_IgnoresOversizedCookies(t *testing.T) {
	f, _ := newTestFlowCookie(t)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: flowCookieName, Value: strings.Repeat("a", maxFlowCookieValueLength+1)})
	assert.Empty(t, f.load(req))
}

func TestFlowCookie_IgnoresUntrustedCookies(t *testing.T) {
	f, now := newTestFlowCookie(t)
	rec := httptest.NewRecorder()
	require.NoError(t, f.add(rec, httptest.NewRequest(http.MethodGet, "/", nil), "s", authorizationRequest{CreatedAt: *now}))
	require.Len(t, f.load(requestWithCookies(rec)), 1)

	tampered := httptest.NewRequest(http.MethodGet, "/", nil)
	cookie := rec.Result().Cookies()[0]
	cookie.Value = "x" + cookie.Value[1:]
	tampered.AddCookie(cookie)
	assert.Empty(t, f.load(tampered), "tampered cookie")

	other, err := newFlowCookie(strings.Repeat("o", 32), true)
	require.NoError(t, err)
	assert.Empty(t, other.load(requestWithCookies(rec)), "cookie made with another secret")

	*now = now.Add(flowTTL + time.Second)
	assert.Empty(t, f.load(requestWithCookies(rec)), "expired flow")
}
