package handler

import (
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
