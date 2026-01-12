package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Client represents an OIDC client configuration.
type Client struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
}

// ProviderConfig represents an OAuth 2.0 provider configuration.
type ProviderConfig struct {
	Name          string   `json:"name"`                     // Unique provider identifier, used in URLs (e.g., "google-app1", "google-app2")
	Type          string   `json:"type,omitempty"`           // Provider type: "twitter", "github", "google" (defaults to Name if not specified)
	ClientID      string   `json:"client_id"`                // OAuth client ID
	ClientSecret  string   `json:"client_secret"`            // OAuth client secret
	CallbackURL   string   `json:"callback_url"`             // OAuth callback URL
	AuthURL       string   `json:"auth_url,omitempty"`       // Custom auth URL (optional)
	TokenURL      string   `json:"token_url,omitempty"`      // Custom token URL (optional)
	UserURL       string   `json:"user_url,omitempty"`       // Custom user info URL (optional)
	Scopes        []string `json:"scopes,omitempty"`         // Custom scopes (optional)
	PrefixSubject *bool    `json:"prefix_subject,omitempty"` // If true, subject is "provider:id"; if false, just "id" (default: true)
}

// Config holds all application configuration.
type Config struct {
	Port int

	// OAuth Providers
	Providers []ProviderConfig

	// OIDC
	OIDCIssuer  string
	OIDCClients []Client

	// Keys
	KeyID             string
	KeyPrivateBase64  string
	KeyPrivatePEM     []byte // Decoded from Base64
	KeyPrivatePEMPath string // Alternative: path to PEM file (for testing)

	// Session
	SessionSecret            string
	SessionSecureCookie      bool // Set to true in production (HTTPS only)
	SessionRedisStoreEnabled bool
	SessionRedisStorePrefix  string

	// Auth Code Store
	AuthCodeRedisStoreEnabled bool
	AuthCodeRedisStorePrefix  string

	// Redis
	RedisEnabled bool
	RedisHost    string
	RedisPort    int
	RedisProto   string
	RedisPass    string
	RedisDB      int

	// Debug
	DebugEnabled             bool
	DebugBaseURL             string
	DebugInspectionEnabled   bool
	DebugCognitoEnabled      bool
	DebugCognitoDomain       string
	DebugCognitoClientID     string
	DebugCognitoClientSecret string
}

// envKeyTransform transforms environment variable names to koanf keys.
// APP_TWITTER_CLIENT_ID -> twitter.client.id
func envKeyTransform(s string) string {
	return strings.ReplaceAll(
		strings.ToLower(strings.TrimPrefix(s, "APP_")),
		"_",
		".",
	)
}

// Load loads configuration from .env files and environment variables.
// The loading order is:
// 1. .env file (if exists)
// 2. .env.local file (if exists)
// 3. Environment variables (override files)
//
// Environment variables use the APP_ prefix and underscore separation.
// Example: APP_OIDC_ISSUER -> oidc.issuer
func Load() (*Config, error) {
	return LoadFromPath("")
}

// LoadFromPath loads configuration from the specified directory.
// If path is empty, uses current directory.
func LoadFromPath(path string) (*Config, error) {
	k := koanf.New(".")

	// Build .env file paths
	envFile := ".env"
	envLocalFile := ".env.local"
	if path != "" {
		envFile = path + "/" + envFile
		envLocalFile = path + "/" + envLocalFile
	}

	// Load .env file if it exists (base configuration)
	if _, err := os.Stat(envFile); err == nil {
		if err := k.Load(file.Provider(envFile), dotenv.ParserEnv("APP_", ".", envKeyTransform)); err != nil {
			return nil, fmt.Errorf("loading .env file: %w", err)
		}
	}

	// Load .env.local file if it exists (local overrides, typically gitignored)
	if _, err := os.Stat(envLocalFile); err == nil {
		if err := k.Load(file.Provider(envLocalFile), dotenv.ParserEnv("APP_", ".", envKeyTransform)); err != nil {
			return nil, fmt.Errorf("loading .env.local file: %w", err)
		}
	}

	// Load environment variables with APP_ prefix (override files)
	err := k.Load(env.Provider("APP_", ".", envKeyTransform), nil)
	if err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	// Also load PORT without prefix (common convention)
	_ = k.Load(env.Provider("", ".", func(s string) string {
		if s == "PORT" {
			return "port"
		}
		return ""
	}), nil)

	cfg := &Config{
		Port: k.Int("port"),

		// OIDC
		OIDCIssuer: k.String("oidc.issuer"),

		// Keys
		KeyID:             k.String("key.id"),
		KeyPrivateBase64:  k.String("key.private.base64"),
		KeyPrivatePEMPath: k.String("key.private.pem.path"),

		// Session
		SessionSecret:            k.String("session.secret"),
		SessionSecureCookie:      k.String("session.secure.cookie") == "1",
		SessionRedisStoreEnabled: k.String("session.redis.store.enabled") == "1",
		SessionRedisStorePrefix:  k.String("session.redis.store.prefix"),

		// Auth Code Store
		AuthCodeRedisStoreEnabled: k.String("auth.code.redis.store.enabled") == "1",
		AuthCodeRedisStorePrefix:  k.String("auth.code.redis.store.prefix"),

		// Redis
		RedisEnabled: k.String("redis.enabled") == "1",
		RedisHost:    k.String("redis.host"),
		RedisPort:    k.Int("redis.port"),
		RedisProto:   k.String("redis.proto"),
		RedisPass:    k.String("redis.pass"),
		RedisDB:      k.Int("redis.db"),

		// Debug
		DebugEnabled:             k.String("debug.enabled") == "1",
		DebugBaseURL:             k.String("debug.base.url"),
		DebugInspectionEnabled:   k.String("debug.inspection.enabled") == "1",
		DebugCognitoEnabled:      k.String("debug.cognito.enabled") == "1",
		DebugCognitoDomain:       k.String("debug.cognito.domain"),
		DebugCognitoClientID:     k.String("debug.cognito.client.id"),
		DebugCognitoClientSecret: k.String("debug.cognito.client.secret"),
	}

	// Set defaults
	if cfg.Port == 0 {
		cfg.Port = 3000
	}

	if cfg.RedisPort == 0 {
		cfg.RedisPort = 6379
	}
	if cfg.RedisProto == "" {
		cfg.RedisProto = "rediss"
	}

	// Parse providers from JSON (new multi-provider format)
	providersJSON := k.String("providers")
	if providersJSON != "" {
		var providers []ProviderConfig
		if err := json.Unmarshal([]byte(providersJSON), &providers); err != nil {
			return nil, fmt.Errorf("parsing providers JSON: %w", err)
		}
		cfg.Providers = providers
	}

	// Apply defaults for providers
	for i := range cfg.Providers {
		// Default Type to Name if not specified
		if cfg.Providers[i].Type == "" {
			cfg.Providers[i].Type = cfg.Providers[i].Name
		}
		// Default PrefixSubject to true if not specified
		if cfg.Providers[i].PrefixSubject == nil {
			defaultTrue := true
			cfg.Providers[i].PrefixSubject = &defaultTrue
		}
	}

	// Parse OIDC clients from JSON
	clientsJSON := k.String("oidc.clients")
	if clientsJSON != "" {
		var clients []Client
		if err := json.Unmarshal([]byte(clientsJSON), &clients); err != nil {
			return nil, fmt.Errorf("parsing OIDC clients JSON: %w", err)
		}
		cfg.OIDCClients = clients
	}

	// Decode private key from Base64
	if cfg.KeyPrivateBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(cfg.KeyPrivateBase64)
		if err != nil {
			return nil, fmt.Errorf("decoding private key from base64: %w", err)
		}
		cfg.KeyPrivatePEM = decoded
	}

	return cfg, nil
}

// Validate checks that required configuration is present.
func (c *Config) Validate() error {
	var missing []string

	if c.SessionSecret == "" {
		missing = append(missing, "APP_SESSION_SECRET")
	}
	if c.OIDCIssuer == "" {
		missing = append(missing, "APP_OIDC_ISSUER")
	}
	if c.KeyID == "" {
		missing = append(missing, "APP_KEY_ID")
	}
	if len(c.KeyPrivatePEM) == 0 && c.KeyPrivatePEMPath == "" {
		missing = append(missing, "APP_KEY_PRIVATE_BASE64 or APP_KEY_PRIVATE_PEM_PATH")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	return nil
}

// GetProviderConfig returns the configuration for a specific provider.
func (c *Config) GetProviderConfig(name string) *ProviderConfig {
	for i := range c.Providers {
		if c.Providers[i].Name == name {
			return &c.Providers[i]
		}
	}
	return nil
}

// ProviderIssuer returns the issuer URL for a specific provider.
// Format: {OIDCIssuer}/providers/{providerName}
func (c *Config) ProviderIssuer(providerName string) string {
	return c.OIDCIssuer + "/providers/" + providerName
}

// LogConfig logs the configuration (with secrets redacted).
func (c *Config) LogConfig(logger *slog.Logger) {
	providerNames := make([]string, len(c.Providers))
	for i, p := range c.Providers {
		providerNames[i] = p.Name
	}

	logger.Info("configuration loaded",
		"port", c.Port,
		"oidc_issuer", c.OIDCIssuer,
		"oidc_clients_count", len(c.OIDCClients),
		"providers", providerNames,
		"key_id", c.KeyID,
		"redis_enabled", c.RedisEnabled,
		"session_redis_store_enabled", c.SessionRedisStoreEnabled,
		"auth_code_redis_store_enabled", c.AuthCodeRedisStoreEnabled,
		"debug_enabled", c.DebugEnabled,
	)
}
