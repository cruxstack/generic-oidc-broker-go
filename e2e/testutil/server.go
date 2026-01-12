package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/handler"
	appMiddleware "github.com/cruxstack/generic-oidc-broker/internal/middleware"
	"github.com/cruxstack/generic-oidc-broker/internal/provider"
	"github.com/cruxstack/generic-oidc-broker/internal/service"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
)

// TestServer represents a test OIDC broker server.
type TestServer struct {
	Server      *http.Server
	URL         string
	Config      *config.Config
	MockTwitter *MockTwitterServer

	listener net.Listener
}

// TestServerConfig holds configuration for creating a test server.
type TestServerConfig struct {
	// Port to listen on (0 for random)
	Port int

	// OIDC clients to register
	Clients []config.Client

	// Whether to start a mock Twitter server
	UseMockTwitter bool

	// Custom issuer URL (defaults to http://localhost:{port})
	Issuer string
}

// NewTestServer creates and starts a new test OIDC broker server.
func NewTestServer(cfg *TestServerConfig) (*TestServer, error) {
	if cfg == nil {
		cfg = &TestServerConfig{}
	}

	// Generate test keys if needed
	keyPair, err := GenerateTestKeyPair(DefaultTestKeyID)
	if err != nil {
		return nil, fmt.Errorf("generating test keys: %w", err)
	}

	// Find available port
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return nil, fmt.Errorf("creating listener: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	// Create mock Twitter server if requested
	var mockTwitter *MockTwitterServer
	twitterAuthURL := provider.TwitterDefaultAuthURL
	twitterTokenURL := provider.TwitterDefaultTokenURL
	twitterUserURL := provider.TwitterDefaultUserURL

	if cfg.UseMockTwitter {
		mockTwitter = NewMockTwitterServer()
		twitterAuthURL = mockTwitter.AuthURL()
		twitterTokenURL = mockTwitter.TokenURL()
		twitterUserURL = mockTwitter.UserURL()

		// Set default mock user
		mockTwitter.SetDefaultUser(&MockTwitterUser{
			ID:              "12345",
			Name:            "Test User",
			Username:        "testuser",
			ProfileImageURL: "https://example.com/avatar.jpg",
		})
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", port)
	}

	// Set default clients if none provided
	clients := cfg.Clients
	if len(clients) == 0 {
		clients = []config.Client{
			{
				ClientID:     "test-client",
				ClientSecret: "test-secret",
				RedirectURIs: []string{
					fmt.Sprintf("http://localhost:%d/callback", port),
					fmt.Sprintf("http://localhost:%d/debug/callback", port),
				},
			},
		}
	}

	// Create config with providers
	appCfg := &config.Config{
		Port: port,

		// Provider config
		Providers: []config.ProviderConfig{
			{
				Name:          "twitter",
				ClientID:      "mock-twitter-client",
				ClientSecret:  "mock-twitter-secret",
				CallbackURL:   fmt.Sprintf("http://localhost:%d/auth/twitter/callback", port),
				AuthURL:       twitterAuthURL,
				TokenURL:      twitterTokenURL,
				UserURL:       twitterUserURL,
				PrefixSubject: ptrBool(true), // Use prefixed subjects by default (e.g., "twitter:12345")
			},
		},

		OIDCIssuer:  issuer,
		OIDCClients: clients,

		KeyID:         keyPair.KeyID,
		KeyPrivatePEM: keyPair.PrivatePEM,

		SessionSecret: "test-session-secret",

		DebugEnabled: true,
		DebugBaseURL: issuer,
	}

	// Create logger (quiet for tests)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Initialize provider registry
	providerRegistry := provider.NewRegistry()
	providerRegistry.RegisterFactory("twitter", provider.TwitterProviderFactory)
	providerRegistry.RegisterFactory("github", provider.GitHubProviderFactory)
	providerRegistry.RegisterFactory("google", provider.GoogleProviderFactory)

	// Create providers from configuration
	for _, provCfg := range appCfg.Providers {
		err := providerRegistry.CreateFromConfig(provider.Config{
			Name:         provCfg.Name,
			ClientID:     provCfg.ClientID,
			ClientSecret: provCfg.ClientSecret,
			CallbackURL:  provCfg.CallbackURL,
			AuthURL:      provCfg.AuthURL,
			TokenURL:     provCfg.TokenURL,
			UserURL:      provCfg.UserURL,
			Scopes:       provCfg.Scopes,
		})
		if err != nil {
			listener.Close()
			if mockTwitter != nil {
				mockTwitter.Close()
			}
			return nil, fmt.Errorf("creating provider %s: %w", provCfg.Name, err)
		}
	}

	// Initialize stores
	authCodeStore := store.NewMemoryAuthCodeStore()

	// Initialize services
	tokenService, err := service.NewTokenService(appCfg, logger)
	if err != nil {
		listener.Close()
		if mockTwitter != nil {
			mockTwitter.Close()
		}
		return nil, fmt.Errorf("creating token service: %w", err)
	}

	clientService := service.NewClientService(appCfg)

	// Initialize handlers
	handlers := handler.NewHandlers(appCfg, tokenService, clientService, authCodeStore, providerRegistry, logger)

	// Setup router
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)

	// Session middleware
	sessionStore, err := appMiddleware.NewSessionStore(appCfg)
	if err != nil {
		listener.Close()
		if mockTwitter != nil {
			mockTwitter.Close()
		}
		return nil, fmt.Errorf("creating session store: %w", err)
	}
	r.Use(appMiddleware.Session(sessionStore, appCfg))

	// Provider-scoped OIDC endpoints
	// Each provider has its own issuer: {base_issuer}/providers/{provider_name}
	r.Get("/providers/{provider}/.well-known/openid-configuration", handlers.ProviderDiscovery)
	r.Get("/providers/{provider}/.well-known/jwks.json", handlers.ProviderJWKS)
	r.Get("/providers/{provider}/authorize", handlers.ProviderAuthorize)
	r.Post("/providers/{provider}/token", handlers.ProviderToken)
	r.Get("/providers/{provider}/userinfo", handlers.ProviderUserinfo)

	// OAuth provider routes - dynamic based on registered providers
	r.Get("/auth/{provider}", handlers.OAuthStart)
	r.Get("/auth/{provider}/callback", handlers.OAuthCallback)

	// Debug routes
	r.Get("/debug/login", handlers.DebugLogin)
	r.Get("/debug/callback", handlers.DebugCallback)

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	ts := &TestServer{
		Server:      srv,
		URL:         fmt.Sprintf("http://localhost:%d", port),
		Config:      appCfg,
		MockTwitter: mockTwitter,
		listener:    listener,
	}

	// Start server in background
	go func() {
		if err := srv.Serve(listener); err != http.ErrServerClosed {
			// Log error but don't panic - test will handle it
		}
	}()

	// Wait for server to be ready
	if err := ts.waitForReady(5 * time.Second); err != nil {
		ts.Close()
		return nil, err
	}

	return ts, nil
}

// Close shuts down the test server.
func (ts *TestServer) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if ts.MockTwitter != nil {
		ts.MockTwitter.Close()
	}

	return ts.Server.Shutdown(ctx)
}

// waitForReady waits for the server to be ready to accept connections.
func (ts *TestServer) waitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(ts.URL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("server not ready after %v", timeout)
}

// ExternalServerURL returns the URL of an external server to test against.
// This is set via the E2E_SERVER_URL environment variable.
func ExternalServerURL() string {
	return os.Getenv("E2E_SERVER_URL")
}

// UseExternalServer returns true if we should test against an external server.
func UseExternalServer() bool {
	return ExternalServerURL() != ""
}

// ptrBool returns a pointer to the given bool value.
func ptrBool(b bool) *bool {
	return &b
}
