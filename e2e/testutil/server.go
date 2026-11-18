// Package testutil runs the broker and the mock provider for end-to-end
// tests.
package testutil

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/internal/app"
	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/mockprovider"
)

// The OIDC client registered with every test broker.
const (
	ClientID     = "test-client"
	ClientSecret = "test-secret"
)

// Server is a running broker whose providers are all backed by one mock
// provider. Its providers are "twitter", "github", "google" and
// "twitter-raw", a Twitter provider with unprefixed subjects.
type Server struct {
	// URL is the broker's base URL, which is also its issuer.
	URL    string
	Config *config.Config
}

// Option adjusts a test broker's configuration.
type Option func(*config.Config)

// NewServer starts a broker and a mock provider. Both are shut down when the
// test ends.
func NewServer(t testing.TB, opts ...Option) *Server {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)

	mock := httptest.NewServer(mockprovider.New(logger, mockprovider.DefaultUsers).Handler())
	t.Cleanup(mock.Close)

	broker := httptest.NewUnstartedServer(nil)
	base := "http://" + broker.Listener.Addr().String()
	unprefixed := false
	cfg := &config.Config{
		Port:   3000,
		Issuer: base,
		Clients: []config.Client{{
			ClientID:     ClientID,
			ClientSecret: ClientSecret,
			RedirectURIs: []string{base + "/callback", base + "/debug/callback"},
		}},
		Providers: []config.Provider{
			mockProviderConfig("twitter", "twitter", base, mock.URL),
			mockProviderConfig("github", "github", base, mock.URL),
			mockProviderConfig("google", "google", base, mock.URL),
			mockProviderConfig("twitter-raw", "twitter", base, mock.URL),
		},
		SigningKeyID:  "test-key",
		SigningKeyPEM: signingKeyPEM(t),
		SessionSecret: strings.Repeat("s", config.MinSessionSecretLength),
		Debug: config.Debug{
			Enabled:      true,
			BaseURL:      base,
			ClientID:     ClientID,
			ClientSecret: ClientSecret,
		},
	}
	cfg.Providers[3].PrefixSubject = &unprefixed
	for _, opt := range opts {
		opt(cfg)
	}

	a, err := app.New(context.Background(), cfg, logger)
	require.NoError(t, err)
	broker.Config.Handler = a.Handler
	broker.Start()
	t.Cleanup(func() {
		broker.Close()
		_ = a.Close()
	})
	return &Server{URL: base, Config: cfg}
}

// mockProviderConfig configures provider name of type kind to use the mock.
func mockProviderConfig(name, kind, base, mockURL string) config.Provider {
	userPath := map[string]string{
		"twitter": "/twitter/user",
		"github":  "/github/user",
		"google":  "/google/userinfo",
	}[kind]
	return config.Provider{
		Name:         name,
		Type:         kind,
		ClientID:     name + "-client",
		ClientSecret: name + "-secret",
		CallbackURL:  base + "/auth/" + name + "/callback",
		AuthURL:      mockURL + "/" + kind + "/authorize",
		TokenURL:     mockURL + "/" + kind + "/token",
		UserURL:      mockURL + userPath,
	}
}

// signingKeyPEM returns an RSA key shared by all tests, since generating one
// is slow.
var signingKeyPEM = func() func(testing.TB) []byte {
	var once sync.Once
	var keyPEM []byte
	return func(t testing.TB) []byte {
		once.Do(func() {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			der, err := x509.MarshalPKCS8PrivateKey(key)
			require.NoError(t, err)
			keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		})
		return keyPEM
	}
}()

// Issuer returns the issuer URL of a provider.
func (s *Server) Issuer(provider string) string {
	return s.Config.ProviderIssuer(provider)
}

// AuthParams returns a valid authorization request for the test client.
func (s *Server) AuthParams() url.Values {
	return url.Values{
		"client_id":     {ClientID},
		"redirect_uri":  {s.URL + "/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"client-state"},
		"nonce":         {"client-nonce"},
	}
}

// TokenForm returns a valid token request for code, authenticating with
// client_secret_post.
func (s *Server) TokenForm(code string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {s.URL + "/callback"},
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
	}
}

// RequestToken posts form to a provider's token endpoint and returns the
// response with its JSON body decoded.
func (s *Server) RequestToken(t testing.TB, provider string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(s.Issuer(provider)+"/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	var body map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return resp, body
}

// RedeemCode exchanges code for tokens and fails the test unless it succeeds.
func (s *Server) RedeemCode(t testing.TB, provider, code string) (idToken, accessToken string) {
	t.Helper()
	resp, body := s.RequestToken(t, provider, s.TokenForm(code))
	require.Equal(t, http.StatusOK, resp.StatusCode, "token response: %v", body)
	return body["id_token"].(string), body["access_token"].(string)
}

// VerifyIDToken checks an ID token's signature against the provider's
// published keys, its issuer and its audience, and returns its claims.
func (s *Server) VerifyIDToken(t testing.TB, provider, raw string) map[string]any {
	t.Helper()
	resp, err := http.Get(s.Issuer(provider) + "/.well-known/jwks.json")
	require.NoError(t, err)
	defer resp.Body.Close()
	var rawSet json.RawMessage
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rawSet))
	keys, err := jwk.Parse(rawSet)
	require.NoError(t, err)

	_, err = jwt.Parse([]byte(raw),
		jwt.WithKeySet(keys),
		jwt.WithIssuer(s.Issuer(provider)),
		jwt.WithAudience(ClientID),
	)
	require.NoError(t, err, "ID token verification")
	return Claims(t, raw)
}

// Claims decodes a JWT's claims without verifying it.
func Claims(t testing.TB, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	require.Len(t, parts, 3, "JWT must have three parts")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}
