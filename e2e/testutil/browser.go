package testutil

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Browser is a user agent for tests: it keeps cookies like a browser but
// doesn't follow redirects, so that tests can inspect every step.
type Browser struct {
	t      testing.TB
	client *http.Client
}

// Response is an HTTP response whose body has been read.
type Response struct {
	*http.Response
	Text string
}

// Location returns the redirect target, resolved against the request URL.
func (r *Response) Location() *url.URL {
	loc, err := r.Response.Location()
	if err != nil {
		return nil
	}
	return loc
}

// NewBrowser returns a browser with an empty cookie jar.
func NewBrowser(t testing.TB) *Browser {
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &Browser{
		t: t,
		client: &http.Client{
			Jar:           jar,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Get requests rawURL.
func (b *Browser) Get(rawURL string) *Response {
	b.t.Helper()
	resp, err := b.client.Get(rawURL)
	require.NoError(b.t, err)
	return read(b.t, resp)
}

// PostForm submits a form to rawURL.
func (b *Browser) PostForm(rawURL string, form url.Values) *Response {
	b.t.Helper()
	resp, err := b.client.PostForm(rawURL, form)
	require.NoError(b.t, err)
	return read(b.t, resp)
}

// Authorize sends an authorization request to a provider of s. On success
// the response redirects to the mock provider.
func (b *Browser) Authorize(s *Server, provider string, params url.Values) *Response {
	b.t.Helper()
	return b.Get(s.Issuer(provider) + "/authorize?" + params.Encode())
}

// SignIn continues from a successful authorization response: it signs in at
// the mock provider as userID and returns the broker's callback response,
// which normally redirects to the client.
func (b *Browser) SignIn(authorize *Response, userID string) *Response {
	b.t.Helper()
	require.Equal(b.t, http.StatusFound, authorize.StatusCode, "authorize response: %s", authorize.Text)

	loginPage := b.Get(authorize.Location().String())
	require.Equal(b.t, http.StatusFound, loginPage.StatusCode, "mock provider: %s", loginPage.Text)
	loginURL := loginPage.Location()

	form := url.Values{"login": {loginURL.Query().Get("login")}, "user_id": {userID}}
	loginURL.RawQuery = ""
	signedIn := b.PostForm(loginURL.String(), form)
	require.Equal(b.t, http.StatusFound, signedIn.StatusCode, "mock provider: %s", signedIn.Text)

	return b.Get(signedIn.Location().String())
}

// Login runs a complete sign-in at a provider of s as userID and returns the
// broker's redirect to the client.
func (b *Browser) Login(s *Server, provider string, params url.Values, userID string) *url.URL {
	b.t.Helper()
	callback := b.SignIn(b.Authorize(s, provider, params), userID)
	require.Equal(b.t, http.StatusFound, callback.StatusCode, "callback response: %s", callback.Text)
	return callback.Location()
}

func read(t testing.TB, resp *http.Response) *Response {
	t.Helper()
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return &Response{Response: resp, Text: strings.TrimSpace(string(body))}
}

// ResponseParams returns the parameters of an authorization response, from
// the fragment if there is one and the query otherwise.
func ResponseParams(t testing.TB, location *url.URL) url.Values {
	t.Helper()
	if location.Fragment != "" {
		params, err := url.ParseQuery(location.EscapedFragment())
		require.NoError(t, err)
		return params
	}
	return location.Query()
}
