// Package provider defines the interface and registry for OAuth 2.0 identity providers.
package provider

import (
	"context"
	"fmt"
	"sort"
	"sync"
)

// UserData holds normalized user information from any OAuth provider.
type UserData struct {
	ID              string `json:"id"`                          // Unique ID from provider
	Provider        string `json:"provider"`                    // Provider name (e.g., "twitter", "github")
	Name            string `json:"name,omitempty"`              // Display name
	Username        string `json:"username,omitempty"`          // Handle/login
	Email           string `json:"email,omitempty"`             // Email (if available)
	EmailVerified   bool   `json:"email_verified,omitempty"`    // Whether email is verified
	ProfileImageURL string `json:"profile_image_url,omitempty"` // Avatar URL
}

// Subject returns the unique subject identifier for OIDC tokens.
// If prefixSubject is true, returns "provider:id" (e.g., "twitter:12345").
// If prefixSubject is false, returns just "id" (e.g., "12345") for backward compatibility.
func (u *UserData) Subject(prefixSubject bool) string {
	if prefixSubject {
		return u.Provider + ":" + u.ID
	}
	return u.ID
}

// TokenResponse holds the tokens returned from an OAuth provider.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	IDToken      string `json:"id_token,omitempty"` // For OIDC providers like Google
}

// Config holds the configuration for an OAuth provider.
type Config struct {
	Name          string   // Unique provider identifier, used in URLs and for registration (e.g., "google-app1")
	Type          string   // Provider type for factory lookup (e.g., "twitter", "github", "google")
	ClientID      string   // OAuth client ID
	ClientSecret  string   // OAuth client secret
	CallbackURL   string   // OAuth callback URL
	AuthURL       string   // Authorization endpoint (optional, uses default if empty)
	TokenURL      string   // Token endpoint (optional, uses default if empty)
	UserURL       string   // User info endpoint (optional, uses default if empty)
	Scopes        []string // OAuth scopes (optional, uses default if empty)
	PrefixSubject bool     // If true, subject is "provider:id"; if false, just "id"
}

// Provider defines the interface for an OAuth 2.0 identity provider.
type Provider interface {
	// Name returns the provider identifier (e.g., "twitter", "github").
	Name() string

	// AuthURL returns the full authorization URL with all required parameters.
	// state: CSRF protection token
	// codeChallenge: PKCE code challenge (S256)
	AuthURL(state, codeChallenge string) string

	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*TokenResponse, error)

	// GetUser fetches user information using the access token.
	GetUser(ctx context.Context, accessToken string) (*UserData, error)

	// Scopes returns the OAuth scopes this provider requests.
	Scopes() []string

	// SupportsPKCE returns whether the provider supports PKCE.
	SupportsPKCE() bool

	// PrefixSubject returns whether the subject should be prefixed with provider name.
	// If true, subject is "provider:id" (e.g., "twitter:12345").
	// If false, subject is just "id" (e.g., "12345").
	PrefixSubject() bool
}

// Factory is a function that creates a Provider from a Config.
type Factory func(cfg Config) (Provider, error)

// Registry manages registered OAuth providers.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
	factories map[string]Factory
}

// NewRegistry creates a new provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]Provider),
		factories: make(map[string]Factory),
	}
}

// RegisterFactory registers a provider factory for a given provider type.
// This allows creating providers from configuration.
func (r *Registry) RegisterFactory(name string, factory Factory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.factories[name] = factory
}

// Register registers a provider instance.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.Name()] = p
}

// Get returns a provider by name.
func (r *Registry) Get(name string) Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.providers[name]
}

// List returns all registered provider names in sorted order for deterministic behavior.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CreateFromConfig creates and registers a provider from configuration.
// The Type field is used to look up the factory, while Name is used as the provider identifier.
func (r *Registry) CreateFromConfig(cfg Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Use Type for factory lookup (defaults to Name if Type is empty)
	factoryType := cfg.Type
	if factoryType == "" {
		factoryType = cfg.Name
	}

	factory, ok := r.factories[factoryType]
	if !ok {
		return fmt.Errorf("unknown provider type: %s", factoryType)
	}

	provider, err := factory(cfg)
	if err != nil {
		return fmt.Errorf("creating provider %s: %w", cfg.Name, err)
	}

	// Register under the provider's Name (not Type)
	r.providers[cfg.Name] = provider
	return nil
}
