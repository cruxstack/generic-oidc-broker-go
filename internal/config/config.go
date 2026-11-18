// Package config loads and validates the broker's configuration.
//
// Settings come from environment variables, optionally seeded from .env and
// .env.local files. Environment variables take precedence over both files,
// and .env.local takes precedence over .env.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// MinSessionSecretLength is the minimum length of APP_SESSION_SECRET in bytes.
const MinSessionSecretLength = 32

// Config is the complete broker configuration.
type Config struct {
	Port     int
	LogLevel slog.Level

	// Issuer is the base URL of the broker. Each provider is exposed as its
	// own OIDC issuer at {Issuer}/providers/{name}.
	Issuer    string
	Clients   []Client
	Providers []Provider

	SigningKeyID  string
	SigningKeyPEM []byte
	// PreviousKeyID and PreviousKeyPEM optionally keep a retired signing key
	// published and trusted during a key rotation. The PEM may hold the
	// public or the private key.
	PreviousKeyID  string
	PreviousKeyPEM []byte

	// SessionSecret protects the short-lived cookie that holds in-progress
	// sign-ins.
	SessionSecret       string
	SessionSecureCookie bool

	ClientIP      ClientIP
	AuthCodeStore AuthCodeStore
	Redis         Redis
	Debug         Debug

	// Warnings lists non-fatal problems found while loading, such as
	// unrecognized settings.
	Warnings []string
}

// Client is an OIDC relying party that may use the broker.
type Client struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

// AllowsRedirectURI reports whether uri exactly matches one of the client's
// registered redirect URIs.
func (c Client) AllowsRedirectURI(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

// Provider configures an upstream OAuth 2.0 identity provider.
type Provider struct {
	// Name identifies the provider in URLs, for example "google-app1".
	Name string `json:"name"`
	// Type selects the implementation: "twitter", "github" or "google".
	// It defaults to Name.
	Type         string `json:"type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	CallbackURL  string `json:"callback_url"`

	// AuthURL, TokenURL, UserURL and Scopes override the type's defaults.
	AuthURL  string   `json:"auth_url"`
	TokenURL string   `json:"token_url"`
	UserURL  string   `json:"user_url"`
	Scopes   []string `json:"scopes"`

	// PrefixSubject controls whether the sub claim is "name:id" (the
	// default) or just the provider's user ID.
	PrefixSubject *bool `json:"prefix_subject"`
}

// SubjectPrefixed reports whether subjects are prefixed with the provider
// name. Prefixing is on unless explicitly disabled.
func (p Provider) SubjectPrefixed() bool {
	return p.PrefixSubject == nil || *p.PrefixSubject
}

// ClientIP selects how the client's IP address is determined, which matters
// for rate limiting and request logs. With no fields set, the TCP peer
// address is used.
type ClientIP struct {
	// Header is a single-IP header that a trusted reverse proxy sets on every
	// request, such as X-Real-IP or CF-Connecting-IP.
	Header string
	// TrustedProxyCIDRs lists the reverse proxies' address ranges. With
	// Header set, the header is only trusted from these peers; without it,
	// X-Forwarded-For is walked past these proxies.
	TrustedProxyCIDRs []string
	// TrustedProxyCount reads X-Forwarded-For assuming exactly this many
	// reverse proxies, for proxies with dynamic addresses.
	TrustedProxyCount int
}

// AuthCodeStore configures where authorization codes are kept.
type AuthCodeStore struct {
	// UseRedis stores codes in Redis instead of process memory. Required
	// when running more than one broker instance.
	UseRedis bool
	// RedisKeyPrefix is prepended to every Redis key.
	RedisKeyPrefix string
}

// Redis configures the Redis connection.
type Redis struct {
	Enabled  bool
	Host     string
	Port     int
	TLS      bool
	Username string
	Password string
	DB       int
}

// Addr returns the Redis address as host:port.
func (r Redis) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

// Debug configures the built-in test pages at /debug/login and
// /debug/callback. They must not be enabled in production.
type Debug struct {
	Enabled bool
	// BaseURL is the broker URL as seen from the browser. Defaults to Issuer.
	BaseURL string
	// ClientID and ClientSecret are the OIDC client the debug pages use.
	// The client must allow {BaseURL}/debug/callback as a redirect URI.
	ClientID     string
	ClientSecret string
	Cognito      Cognito
}

// Cognito configures an optional Amazon Cognito user pool for the debug
// pages, to test the broker as a Cognito identity provider.
type Cognito struct {
	Enabled      bool
	Domain       string
	ClientID     string
	ClientSecret string
}

// ProviderIssuer returns the OIDC issuer for the named provider.
func (c *Config) ProviderIssuer(providerName string) string {
	return c.Issuer + "/providers/" + providerName
}

// Client returns the client with the given ID.
func (c *Config) Client(clientID string) (Client, bool) {
	for _, client := range c.Clients {
		if client.ClientID == clientID {
			return client, true
		}
	}
	return Client{}, false
}

// LogValue implements slog.LogValuer. Secrets are omitted.
func (c *Config) LogValue() slog.Value {
	providers := make([]string, len(c.Providers))
	for i, p := range c.Providers {
		providers[i] = p.Name + " (" + p.Type + ")"
	}
	return slog.GroupValue(
		slog.Int("port", c.Port),
		slog.String("log_level", c.LogLevel.String()),
		slog.String("issuer", c.Issuer),
		slog.Int("clients", len(c.Clients)),
		slog.Any("providers", providers),
		slog.String("signing_key_id", c.SigningKeyID),
		slog.Bool("session_secure_cookie", c.SessionSecureCookie),
		slog.Bool("auth_code_store_redis", c.AuthCodeStore.UseRedis),
		slog.Bool("debug_enabled", c.Debug.Enabled),
	)
}

var providerNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Validate reports every configuration problem it finds.
func (c *Config) Validate() error {
	var errs []error
	fail := func(format string, args ...any) {
		errs = append(errs, fmt.Errorf(format, args...))
	}

	if c.Port < 1 || c.Port > 65535 {
		fail("PORT: %d is not a valid port", c.Port)
	}
	if err := validateIssuer(c.Issuer); err != nil {
		fail("APP_OIDC_ISSUER: %w", err)
	}
	if c.SigningKeyID == "" {
		fail("APP_KEY_ID is required")
	}
	if len(c.SigningKeyPEM) == 0 {
		fail("a signing key is required: set APP_KEY_PRIVATE_BASE64 or APP_KEY_PRIVATE_PEM_PATH")
	}
	switch {
	case (c.PreviousKeyID == "") != (len(c.PreviousKeyPEM) == 0):
		fail("APP_KEY_PREVIOUS_ID and APP_KEY_PREVIOUS_BASE64 must be set together")
	case c.PreviousKeyID != "" && c.PreviousKeyID == c.SigningKeyID:
		fail("APP_KEY_PREVIOUS_ID must differ from APP_KEY_ID")
	}
	if len(c.SessionSecret) < MinSessionSecretLength {
		fail("APP_SESSION_SECRET must be at least %d characters (generate one with: openssl rand -base64 32)", MinSessionSecretLength)
	}

	errs = append(errs, c.validateClients()...)
	errs = append(errs, c.validateProviders()...)
	errs = append(errs, c.validateClientIP()...)

	if c.AuthCodeStore.UseRedis && !c.Redis.Enabled {
		fail("APP_AUTH_CODE_REDIS_STORE_ENABLED requires APP_REDIS_ENABLED")
	}
	if c.Redis.Enabled {
		if c.Redis.Host == "" {
			fail("APP_REDIS_HOST is required when Redis is enabled")
		}
		if c.Redis.Port < 1 || c.Redis.Port > 65535 {
			fail("APP_REDIS_PORT: %d is not a valid port", c.Redis.Port)
		}
	}

	if c.Debug.Enabled {
		errs = append(errs, c.validateDebug()...)
	}

	return errors.Join(errs...)
}

func (c *Config) validateClients() []error {
	if len(c.Clients) == 0 {
		return []error{errors.New("APP_OIDC_CLIENTS must configure at least one client")}
	}
	var errs []error
	seen := map[string]bool{}
	for i, client := range c.Clients {
		where := fmt.Sprintf("APP_OIDC_CLIENTS[%d]", i)
		switch {
		case client.ClientID == "":
			errs = append(errs, fmt.Errorf("%s: client_id is required", where))
		case seen[client.ClientID]:
			errs = append(errs, fmt.Errorf("%s: duplicate client_id %q", where, client.ClientID))
		}
		seen[client.ClientID] = true
		if client.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s: client_secret is required", where))
		}
		if len(client.RedirectURIs) == 0 {
			errs = append(errs, fmt.Errorf("%s: at least one redirect_uris entry is required", where))
		}
		for _, uri := range client.RedirectURIs {
			if err := validateRedirectURI(uri); err != nil {
				errs = append(errs, fmt.Errorf("%s: redirect URI %q: %w", where, uri, err))
			}
		}
	}
	return errs
}

func (c *Config) validateProviders() []error {
	if len(c.Providers) == 0 {
		return []error{errors.New("APP_PROVIDERS must configure at least one provider")}
	}
	var errs []error
	seen := map[string]bool{}
	for i, p := range c.Providers {
		where := fmt.Sprintf("APP_PROVIDERS[%d]", i)
		switch {
		case !providerNamePattern.MatchString(p.Name):
			errs = append(errs, fmt.Errorf("%s: name %q must be non-empty and contain only letters, digits, '-' and '_'", where, p.Name))
		case seen[p.Name]:
			errs = append(errs, fmt.Errorf("%s: duplicate name %q", where, p.Name))
		}
		seen[p.Name] = true
		if p.Type == "" {
			errs = append(errs, fmt.Errorf("%s: type is required", where))
		}
		if p.ClientID == "" || p.ClientSecret == "" {
			errs = append(errs, fmt.Errorf("%s: client_id and client_secret are required", where))
		}
		if err := validateAbsoluteURL(p.CallbackURL); err != nil {
			errs = append(errs, fmt.Errorf("%s: callback_url: %w", where, err))
		}
		for _, override := range []struct{ field, value string }{
			{"auth_url", p.AuthURL}, {"token_url", p.TokenURL}, {"user_url", p.UserURL},
		} {
			if override.value == "" {
				continue
			}
			if err := validateAbsoluteURL(override.value); err != nil {
				errs = append(errs, fmt.Errorf("%s: %s: %w", where, override.field, err))
			}
		}
	}
	return errs
}

func (c *Config) validateClientIP() []error {
	var errs []error
	for _, cidr := range c.ClientIP.TrustedProxyCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			errs = append(errs, fmt.Errorf("APP_TRUSTED_PROXY_CIDRS: %q is not a CIDR prefix", cidr))
		}
	}
	if c.ClientIP.TrustedProxyCount < 0 {
		errs = append(errs, errors.New("APP_TRUSTED_PROXY_COUNT must not be negative"))
	}
	if c.ClientIP.TrustedProxyCount > 0 && (c.ClientIP.Header != "" || len(c.ClientIP.TrustedProxyCIDRs) > 0) {
		errs = append(errs, errors.New("APP_TRUSTED_PROXY_COUNT cannot be combined with APP_CLIENT_IP_HEADER or APP_TRUSTED_PROXY_CIDRS"))
	}
	return errs
}

func (c *Config) validateDebug() []error {
	var errs []error
	if err := validateAbsoluteURL(c.Debug.BaseURL); err != nil {
		errs = append(errs, fmt.Errorf("APP_DEBUG_BASE_URL: %w", err))
	}
	client, ok := c.Client(c.Debug.ClientID)
	switch {
	case c.Debug.ClientID == "" || c.Debug.ClientSecret == "":
		errs = append(errs, errors.New("APP_DEBUG_CLIENT_ID and APP_DEBUG_CLIENT_SECRET are required when debug pages are enabled"))
	case !ok:
		errs = append(errs, fmt.Errorf("APP_DEBUG_CLIENT_ID: client %q is not in APP_OIDC_CLIENTS", c.Debug.ClientID))
	case !client.AllowsRedirectURI(c.Debug.BaseURL + "/debug/callback"):
		errs = append(errs, fmt.Errorf("APP_DEBUG_CLIENT_ID: client %q must allow redirect URI %s/debug/callback", c.Debug.ClientID, c.Debug.BaseURL))
	}
	if cognito := c.Debug.Cognito; cognito.Enabled {
		if cognito.ClientID == "" || cognito.ClientSecret == "" {
			errs = append(errs, errors.New("APP_DEBUG_COGNITO_CLIENT_ID and APP_DEBUG_COGNITO_CLIENT_SECRET are required when Cognito debugging is enabled"))
		}
		if err := validateAbsoluteURL(cognito.Domain); err != nil {
			errs = append(errs, fmt.Errorf("APP_DEBUG_COGNITO_DOMAIN: %w", err))
		}
	}
	return errs
}

// validateIssuer checks the rules of OIDC Discovery §3: an https (or, for
// local development, http) URL with no query or fragment. A trailing slash
// is rejected because provider issuers are formed by appending a path.
func validateIssuer(issuer string) error {
	if err := validateAbsoluteURL(issuer); err != nil {
		return err
	}
	u, _ := url.Parse(issuer)
	switch {
	case u.RawQuery != "" || u.Fragment != "":
		return errors.New("must not contain a query or fragment")
	case strings.HasSuffix(issuer, "/"):
		return errors.New("must not end with a slash")
	}
	return nil
}

func validateRedirectURI(uri string) error {
	u, err := url.Parse(uri)
	switch {
	case err != nil || !u.IsAbs() || u.Host == "":
		return errors.New("must be an absolute URL")
	case u.Fragment != "":
		return errors.New("must not contain a fragment")
	}
	return nil
}

func validateAbsoluteURL(raw string) error {
	if raw == "" {
		return errors.New("is required")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an absolute http(s) URL", raw)
	}
	return nil
}
