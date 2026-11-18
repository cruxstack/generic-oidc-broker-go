package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/knadh/koanf/parsers/dotenv"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Load reads the configuration from dir/.env, dir/.env.local and the
// environment, applies defaults and validates the result.
func Load(dir string) (*Config, error) {
	k := koanf.New(".")
	for _, name := range []string{".env", ".env.local"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err := k.Load(file.Provider(path), dotenv.Parser()); err != nil {
			return nil, fmt.Errorf("loading %s: %w", path, err)
		}
	}
	if err := k.Load(env.Provider("", ".", keepBrokerVariable), nil); err != nil {
		return nil, fmt.Errorf("loading environment: %w", err)
	}

	cfg, err := parse(k)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// keepBrokerVariable selects the environment variables the broker reads.
func keepBrokerVariable(name string) string {
	if name == "PORT" || strings.HasPrefix(name, "APP_") {
		return name
	}
	return ""
}

// parse builds a Config from the loaded settings, reporting every value that
// cannot be parsed.
func parse(k *koanf.Koanf) (*Config, error) {
	r := &reader{k: k, used: map[string]bool{}}

	cfg := &Config{
		Port:     r.int("PORT", 3000),
		LogLevel: r.logLevel("APP_LOG_LEVEL", slog.LevelInfo),

		Issuer:       r.string("APP_OIDC_ISSUER", ""),
		SigningKeyID: r.string("APP_KEY_ID", ""),

		SessionSecret: r.string("APP_SESSION_SECRET", ""),

		ClientIP: ClientIP{
			Header:            r.string("APP_CLIENT_IP_HEADER", ""),
			TrustedProxyCIDRs: r.list("APP_TRUSTED_PROXY_CIDRS"),
			TrustedProxyCount: r.int("APP_TRUSTED_PROXY_COUNT", 0),
		},

		AuthCodeStore: AuthCodeStore{
			UseRedis:       r.bool("APP_AUTH_CODE_REDIS_STORE_ENABLED", false),
			RedisKeyPrefix: r.string("APP_AUTH_CODE_REDIS_STORE_PREFIX", "authcode:"),
		},

		Redis: Redis{
			Enabled:  r.bool("APP_REDIS_ENABLED", false),
			Host:     r.string("APP_REDIS_HOST", "localhost"),
			Port:     r.int("APP_REDIS_PORT", 6379),
			TLS:      r.redisTLS("APP_REDIS_PROTO"),
			Username: r.string("APP_REDIS_USER", ""),
			Password: r.string("APP_REDIS_PASS", ""),
			DB:       r.int("APP_REDIS_DB", 0),
		},
	}

	// Cookies default to Secure whenever the broker is served over HTTPS.
	cfg.SessionSecureCookie = r.bool("APP_SESSION_SECURE_COOKIE", strings.HasPrefix(cfg.Issuer, "https://"))

	cfg.SigningKeyPEM = r.signingKey()
	cfg.PreviousKeyID = r.string("APP_KEY_PREVIOUS_ID", "")
	cfg.PreviousKeyPEM = r.base64("APP_KEY_PREVIOUS_BASE64")
	r.json("APP_OIDC_CLIENTS", &cfg.Clients)
	r.json("APP_PROVIDERS", &cfg.Providers)
	for i := range cfg.Providers {
		if cfg.Providers[i].Type == "" {
			cfg.Providers[i].Type = cfg.Providers[i].Name
		}
	}

	cfg.Debug = Debug{
		Enabled:      r.bool("APP_DEBUG_ENABLED", false),
		BaseURL:      r.string("APP_DEBUG_BASE_URL", cfg.Issuer),
		ClientID:     r.string("APP_DEBUG_CLIENT_ID", ""),
		ClientSecret: r.string("APP_DEBUG_CLIENT_SECRET", ""),
		Cognito: Cognito{
			Enabled:      r.bool("APP_DEBUG_COGNITO_ENABLED", false),
			Domain:       r.string("APP_DEBUG_COGNITO_DOMAIN", ""),
			ClientID:     r.string("APP_DEBUG_COGNITO_CLIENT_ID", ""),
			ClientSecret: r.string("APP_DEBUG_COGNITO_CLIENT_SECRET", ""),
		},
	}

	if len(r.errs) > 0 {
		return nil, errors.Join(r.errs...)
	}

	cfg.Warnings = r.unusedSettings()
	if cfg.Redis.Enabled && !cfg.AuthCodeStore.UseRedis {
		cfg.Warnings = append(cfg.Warnings, "APP_REDIS_ENABLED is set but nothing uses Redis; set APP_AUTH_CODE_REDIS_STORE_ENABLED to store authorization codes in it")
	}
	return cfg, nil
}

// reader reads typed settings, collecting parse errors and remembering which
// settings were read so that unknown ones can be reported.
type reader struct {
	k    *koanf.Koanf
	errs []error
	used map[string]bool
}

func (r *reader) fail(key, format string, args ...any) {
	r.errs = append(r.errs, fmt.Errorf("%s: %s", key, fmt.Sprintf(format, args...)))
}

// string returns the trimmed setting, or fallback when it is unset or empty.
func (r *reader) string(key, fallback string) string {
	r.used[key] = true
	if value := strings.TrimSpace(r.k.String(key)); value != "" {
		return value
	}
	return fallback
}

func (r *reader) bool(key string, fallback bool) bool {
	value := r.string(key, "")
	if value == "" {
		return fallback
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		r.fail(key, "%q is not a boolean (use true/false or 1/0)", value)
		return fallback
	}
	return b
}

func (r *reader) int(key string, fallback int) int {
	value := r.string(key, "")
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		r.fail(key, "%q is not an integer", value)
		return fallback
	}
	return n
}

// list returns a comma-separated setting as a slice, skipping empty items.
func (r *reader) list(key string) []string {
	var items []string
	for item := range strings.SplitSeq(r.string(key, ""), ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

func (r *reader) json(key string, dst any) {
	value := r.string(key, "")
	if value == "" {
		return
	}
	if err := json.Unmarshal([]byte(value), dst); err != nil {
		r.fail(key, "invalid JSON: %v", err)
	}
}

func (r *reader) logLevel(key string, fallback slog.Level) slog.Level {
	value := r.string(key, "")
	if value == "" {
		return fallback
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(value)); err != nil {
		r.fail(key, "%q is not a log level (use debug, info, warn or error)", value)
		return fallback
	}
	return level
}

func (r *reader) redisTLS(key string) bool {
	switch proto := r.string(key, "rediss"); proto {
	case "rediss":
		return true
	case "redis":
		return false
	default:
		r.fail(key, "%q must be redis or rediss", proto)
		return true
	}
}

// base64 returns the decoded value of a base64-encoded setting.
func (r *reader) base64(key string) []byte {
	encoded := r.string(key, "")
	if encoded == "" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		r.fail(key, "invalid base64: %v", err)
	}
	return decoded
}

// signingKey returns the PEM-encoded signing key from APP_KEY_PRIVATE_BASE64
// or, if that is unset, from the file at APP_KEY_PRIVATE_PEM_PATH.
func (r *reader) signingKey() []byte {
	encoded := r.base64("APP_KEY_PRIVATE_BASE64")
	path := r.string("APP_KEY_PRIVATE_PEM_PATH", "")
	switch {
	case encoded != nil:
		return encoded
	case path != "":
		pem, err := os.ReadFile(path)
		if err != nil {
			r.fail("APP_KEY_PRIVATE_PEM_PATH", "%v", err)
		}
		return pem
	}
	return nil
}

// unusedSettings returns a warning for each APP_ setting the broker does not
// recognize, which usually means a typo or a removed setting.
func (r *reader) unusedSettings() []string {
	var warnings []string
	for _, key := range r.k.Keys() {
		if strings.HasPrefix(key, "APP_") && !r.used[key] {
			warnings = append(warnings, fmt.Sprintf("unknown setting %s is ignored", key))
		}
	}
	slices.Sort(warnings)
	return warnings
}
