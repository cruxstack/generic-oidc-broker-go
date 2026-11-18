package e2e

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/e2e/testutil"
	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

var hrefPattern = regexp.MustCompile(`href="([^"]+)"`)

func TestDebugPages(t *testing.T) {
	s := testutil.NewServer(t)
	browser := testutil.NewBrowser(t)

	login := browser.Get(s.URL + "/debug/login")
	require.Equal(t, http.StatusOK, login.StatusCode)
	assert.Contains(t, login.Header.Get("Content-Security-Policy"), "default-src 'none'")
	assert.NotContains(t, login.Text, "<script", "debug pages must not load scripts")

	var signInURL string
	for _, match := range hrefPattern.FindAllStringSubmatch(login.Text, -1) {
		if link := html.UnescapeString(match[1]); strings.Contains(link, "/providers/github/authorize?") {
			signInURL = link
		}
	}
	require.NotEmpty(t, signInURL, "the login page must link to a GitHub sign-in")

	callback := browser.SignIn(browser.Get(signInURL), "1001")
	require.Equal(t, http.StatusFound, callback.StatusCode, callback.Text)
	require.Equal(t, "/debug/callback", callback.Location().Path)

	page := browser.Get(callback.Location().String())
	require.Equal(t, http.StatusOK, page.StatusCode)
	assert.NotContains(t, page.Text, "Could not redeem")
	assert.NotContains(t, page.Text, "request failed")
	assert.Contains(t, page.Text, "&#34;sub&#34;: &#34;github:1001&#34;", "ID token claims")
	assert.Contains(t, page.Text, "&#34;email&#34;: &#34;alice@example.com&#34;", "userinfo response")
}

func TestDebugPages_Disabled(t *testing.T) {
	s := testutil.NewServer(t, func(c *config.Config) { c.Debug.Enabled = false })

	resp := testutil.NewBrowser(t).Get(s.URL + "/debug/login")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
