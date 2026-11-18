package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// settings returns a koanf instance holding the given settings.
func settings(t *testing.T, values map[string]string) *koanf.Koanf {
	t.Helper()
	k := koanf.New(".")
	for key, value := range values {
		require.NoError(t, k.Set(key, value))
	}
	return k
}

// validSettings is a minimal valid configuration.
func validSettings() map[string]string {
	return map[string]string{
		"APP_OIDC_ISSUER":        "https://broker.example.com",
		"APP_OIDC_CLIENTS":       `[{"client_id":"app","client_secret":"secret","redirect_uris":["https://app.example.com/callback"]}]`,
		"APP_PROVIDERS":          `[{"name":"github","client_id":"id","client_secret":"secret","callback_url":"https://broker.example.com/auth/github/callback"}]`,
		"APP_KEY_ID":             "key-1",
		"APP_KEY_PRIVATE_BASE64": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t", // any valid base64 parses
		"APP_SESSION_SECRET":     strings.Repeat("x", MinSessionSecretLength),
	}
}

func TestParse_Defaults(t *testing.T) {
	cfg, err := parse(settings(t, validSettings()))
	require.NoError(t, err)

	assert.Equal(t, 3000, cfg.Port)
	assert.Equal(t, slog.LevelInfo, cfg.LogLevel)
	assert.True(t, cfg.SessionSecureCookie, "cookies default to Secure for an https issuer")
	assert.Equal(t, "github", cfg.Providers[0].Type, "type defaults to the name")
	assert.True(t, cfg.Providers[0].SubjectPrefixed())
	assert.Equal(t, "authcode:", cfg.AuthCodeStore.RedisKeyPrefix)
	assert.Equal(t, Redis{Host: "localhost", Port: 6379, TLS: true}, cfg.Redis)
	assert.Equal(t, "https://broker.example.com", cfg.Debug.BaseURL)
	assert.Empty(t, cfg.Warnings)
	require.NoError(t, cfg.Validate())
}

func TestParse_Values(t *testing.T) {
	values := validSettings()
	values["PORT"] = "8080"
	values["APP_LOG_LEVEL"] = "debug"
	values["APP_OIDC_ISSUER"] = "http://localhost:8080"
	values["APP_SESSION_SECURE_COOKIE"] = "true"
	values["APP_TRUSTED_PROXY_CIDRS"] = " 10.0.0.0/8, ,192.168.0.0/16 "
	values["APP_REDIS_PROTO"] = "redis"
	values["APP_PROVIDERS"] = `[{"name":"google-app1","type":"google","prefix_subject":false,"client_id":"id","client_secret":"s","callback_url":"http://localhost:8080/auth/google-app1/callback"}]`

	cfg, err := parse(settings(t, values))
	require.NoError(t, err)

	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, slog.LevelDebug, cfg.LogLevel)
	assert.True(t, cfg.SessionSecureCookie)
	assert.Equal(t, []string{"10.0.0.0/8", "192.168.0.0/16"}, cfg.ClientIP.TrustedProxyCIDRs)
	assert.False(t, cfg.Redis.TLS)
	assert.Equal(t, "google", cfg.Providers[0].Type)
	assert.False(t, cfg.Providers[0].SubjectPrefixed())
}

func TestParse_SecureCookieDefaultsToFalseForHTTP(t *testing.T) {
	values := validSettings()
	values["APP_OIDC_ISSUER"] = "http://localhost:3000"

	cfg, err := parse(settings(t, values))
	require.NoError(t, err)
	assert.False(t, cfg.SessionSecureCookie)
}

func TestParse_InvalidValues(t *testing.T) {
	tests := map[string]string{
		"APP_SESSION_SECURE_COOKIE": "yes please",
		"PORT":                      "eighty",
		"APP_LOG_LEVEL":             "loud",
		"APP_REDIS_PROTO":           "http",
		"APP_OIDC_CLIENTS":          "[{",
		"APP_KEY_PRIVATE_BASE64":    "not base64!",
	}
	for key, value := range tests {
		t.Run(key, func(t *testing.T) {
			values := validSettings()
			values[key] = value
			_, err := parse(settings(t, values))
			require.Error(t, err)
			assert.Contains(t, err.Error(), key)
		})
	}
}

func TestParse_WarnsAboutUnknownSettings(t *testing.T) {
	values := validSettings()
	values["APP_SESSION_REDIS_STORE_ENABLED"] = "1"
	values["APP_SESION_SECRET"] = "typo"
	values["UNRELATED"] = "ignored"

	cfg, err := parse(settings(t, values))
	require.NoError(t, err)
	assert.Equal(t, []string{
		"unknown setting APP_SESION_SECRET is ignored",
		"unknown setting APP_SESSION_REDIS_STORE_ENABLED is ignored",
	}, cfg.Warnings)
}

func TestParse_SigningKeyFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(path, []byte("PEM"), 0o600))
	values := validSettings()
	delete(values, "APP_KEY_PRIVATE_BASE64")
	values["APP_KEY_PRIVATE_PEM_PATH"] = path

	cfg, err := parse(settings(t, values))
	require.NoError(t, err)
	assert.Equal(t, []byte("PEM"), cfg.SigningKeyPEM)

	values["APP_KEY_PRIVATE_PEM_PATH"] = filepath.Join(t.TempDir(), "missing.pem")
	_, err = parse(settings(t, values))
	assert.ErrorContains(t, err, "APP_KEY_PRIVATE_PEM_PATH")
}

func TestLoad_Precedence(t *testing.T) {
	dir := t.TempDir()
	var env strings.Builder
	for key, value := range validSettings() {
		env.WriteString(key + "=" + value + "\n")
	}
	env.WriteString("PORT=1111\nAPP_LOG_LEVEL=warn\n")
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte(env.String()), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env.local"), []byte("PORT=2222\nAPP_LOG_LEVEL=error\n"), 0o600))
	t.Setenv("APP_LOG_LEVEL", "debug")

	cfg, err := Load(dir)
	require.NoError(t, err)
	assert.Equal(t, 2222, cfg.Port, ".env.local overrides .env")
	assert.Equal(t, slog.LevelDebug, cfg.LogLevel, "the environment overrides both files")
}

func TestExampleEnvFileParses(t *testing.T) {
	k := koanf.New(".")
	require.NoError(t, k.Load(file.Provider("../../.env.example"), dotenv.Parser()))

	cfg, err := parse(k)
	require.NoError(t, err)
	assert.Empty(t, cfg.Warnings, "the example must only use known settings")
	assert.Empty(t, cfg.SigningKeyPEM, "the example must not ship a signing key")
	assert.Empty(t, cfg.SessionSecret, "the example must not ship a session secret")
	assert.False(t, cfg.Debug.Enabled, "the example must not enable debug pages")
}

func validConfig(t *testing.T) *Config {
	t.Helper()
	cfg, err := parse(settings(t, validSettings()))
	require.NoError(t, err)
	return cfg
}

func TestValidate(t *testing.T) {
	require.NoError(t, validConfig(t).Validate())

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{"port", func(c *Config) { c.Port = 0 }, "PORT"},
		{"missing issuer", func(c *Config) { c.Issuer = "" }, "APP_OIDC_ISSUER"},
		{"relative issuer", func(c *Config) { c.Issuer = "/broker" }, "APP_OIDC_ISSUER"},
		{"issuer trailing slash", func(c *Config) { c.Issuer = "https://broker.example.com/" }, "must not end with a slash"},
		{"issuer query", func(c *Config) { c.Issuer = "https://broker.example.com?x=1" }, "query"},
		{"key ID", func(c *Config) { c.SigningKeyID = "" }, "APP_KEY_ID"},
		{"signing key", func(c *Config) { c.SigningKeyPEM = nil }, "signing key is required"},
		{"previous key without ID", func(c *Config) { c.PreviousKeyPEM = []byte("PEM") }, "must be set together"},
		{"previous key reusing ID", func(c *Config) { c.PreviousKeyID, c.PreviousKeyPEM = c.SigningKeyID, []byte("PEM") }, "must differ"},
		{"short session secret", func(c *Config) { c.SessionSecret = "secret" }, "APP_SESSION_SECRET"},
		{"no clients", func(c *Config) { c.Clients = nil }, "at least one client"},
		{"client ID", func(c *Config) { c.Clients[0].ClientID = "" }, "client_id is required"},
		{"client secret", func(c *Config) { c.Clients[0].ClientSecret = "" }, "client_secret is required"},
		{"duplicate client", func(c *Config) { c.Clients = append(c.Clients, c.Clients[0]) }, "duplicate client_id"},
		{"no redirect URIs", func(c *Config) { c.Clients[0].RedirectURIs = nil }, "redirect_uris"},
		{"relative redirect URI", func(c *Config) { c.Clients[0].RedirectURIs = []string{"/callback"} }, "absolute URL"},
		{"redirect URI fragment", func(c *Config) { c.Clients[0].RedirectURIs = []string{"https://a.example/#x"} }, "fragment"},
		{"no providers", func(c *Config) { c.Providers = nil }, "at least one provider"},
		{"provider name", func(c *Config) { c.Providers[0].Name = "git hub" }, "name"},
		{"duplicate provider", func(c *Config) { c.Providers = append(c.Providers, c.Providers[0]) }, "duplicate name"},
		{"provider credentials", func(c *Config) { c.Providers[0].ClientSecret = "" }, "client_secret are required"},
		{"provider callback", func(c *Config) { c.Providers[0].CallbackURL = "" }, "callback_url"},
		{"provider override URL", func(c *Config) { c.Providers[0].TokenURL = "ftp://x" }, "token_url"},
		{"proxy CIDR", func(c *Config) { c.ClientIP.TrustedProxyCIDRs = []string{"10.0.0.1"} }, "APP_TRUSTED_PROXY_CIDRS"},
		{"proxy count with header", func(c *Config) { c.ClientIP.TrustedProxyCount = 1; c.ClientIP.Header = "X-Real-IP" }, "cannot be combined"},
		{"redis store without redis", func(c *Config) { c.AuthCodeStore.UseRedis = true }, "requires APP_REDIS_ENABLED"},
		{"redis host", func(c *Config) { c.Redis.Enabled = true; c.Redis.Host = "" }, "APP_REDIS_HOST"},
		{"debug client", func(c *Config) { c.Debug.Enabled = true }, "APP_DEBUG_CLIENT_ID"},
		{"debug unknown client", func(c *Config) {
			c.Debug = Debug{Enabled: true, BaseURL: c.Issuer, ClientID: "nope", ClientSecret: "s"}
		}, "not in APP_OIDC_CLIENTS"},
		{"debug redirect URI", func(c *Config) {
			c.Debug = Debug{Enabled: true, BaseURL: c.Issuer, ClientID: "app", ClientSecret: "s"}
		}, "/debug/callback"},
		{"cognito", func(c *Config) {
			c.Clients[0].RedirectURIs = append(c.Clients[0].RedirectURIs, c.Issuer+"/debug/callback")
			c.Debug = Debug{Enabled: true, BaseURL: c.Issuer, ClientID: "app", ClientSecret: "s", Cognito: Cognito{Enabled: true}}
		}, "APP_DEBUG_COGNITO"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig(t)
			tt.mutate(cfg)
			assert.ErrorContains(t, cfg.Validate(), tt.wantErr)
		})
	}
}

func TestProviderIssuer(t *testing.T) {
	cfg := &Config{Issuer: "https://broker.example.com"}
	assert.Equal(t, "https://broker.example.com/providers/github", cfg.ProviderIssuer("github"))
}
