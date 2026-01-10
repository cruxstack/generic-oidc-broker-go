package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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

func main() {
	// Setup structured logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("application error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("validating config: %w", err)
	}

	cfg.LogConfig(logger)

	// Initialize provider registry and register configured providers
	providerRegistry := provider.NewRegistry()

	// Register built-in provider factories
	providerRegistry.RegisterFactory("twitter", provider.TwitterProviderFactory)
	providerRegistry.RegisterFactory("github", provider.GitHubProviderFactory)
	providerRegistry.RegisterFactory("google", provider.GoogleProviderFactory)

	// Create providers from configuration
	for _, provCfg := range cfg.Providers {
		prefixSubject := true // default
		if provCfg.PrefixSubject != nil {
			prefixSubject = *provCfg.PrefixSubject
		}
		err := providerRegistry.CreateFromConfig(provider.Config{
			Name:          provCfg.Name,
			Type:          provCfg.Type,
			ClientID:      provCfg.ClientID,
			ClientSecret:  provCfg.ClientSecret,
			CallbackURL:   provCfg.CallbackURL,
			AuthURL:       provCfg.AuthURL,
			TokenURL:      provCfg.TokenURL,
			UserURL:       provCfg.UserURL,
			Scopes:        provCfg.Scopes,
			PrefixSubject: prefixSubject,
		})
		if err != nil {
			return fmt.Errorf("creating provider %s: %w", provCfg.Name, err)
		}
		logger.Info("registered OAuth provider", "name", provCfg.Name, "type", provCfg.Type, "prefix_subject", prefixSubject)
	}

	if len(providerRegistry.List()) == 0 {
		logger.Warn("no OAuth providers configured")
	}

	// Initialize auth code store (Redis or in-memory)
	var authCodeStore store.AuthCodeStore
	if cfg.AuthCodeRedisStoreEnabled && cfg.RedisEnabled {
		logger.Info("using Redis auth code store")
		redisStore, err := store.NewRedisAuthCodeStore(&store.RedisConfig{
			Host:   cfg.RedisHost,
			Port:   cfg.RedisPort,
			Proto:  cfg.RedisProto,
			Pass:   cfg.RedisPass,
			Prefix: cfg.AuthCodeRedisStorePrefix,
		})
		if err != nil {
			return fmt.Errorf("creating Redis auth code store: %w", err)
		}
		defer redisStore.Close()
		authCodeStore = redisStore
	} else {
		logger.Info("using in-memory auth code store")
		memStore := store.NewMemoryAuthCodeStore()
		defer memStore.Close()
		authCodeStore = memStore
	}

	// Initialize services
	tokenService, err := service.NewTokenService(cfg, logger)
	if err != nil {
		return fmt.Errorf("creating token service: %w", err)
	}

	clientService := service.NewClientService(cfg)

	// Initialize handlers
	handlers := handler.NewHandlers(cfg, tokenService, clientService, authCodeStore, providerRegistry, logger)

	// Initialize rate limiter for /userinfo (100 req / 15 min)
	userinfoRateLimiter := appMiddleware.UserinfoRateLimiter()
	defer userinfoRateLimiter.Stop()

	// Setup router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(appMiddleware.Logger(logger))
	r.Use(middleware.Recoverer)

	// Session middleware
	sessionStore, err := appMiddleware.NewSessionStore(cfg)
	if err != nil {
		return fmt.Errorf("creating session store: %w", err)
	}
	r.Use(appMiddleware.Session(sessionStore, cfg))

	// Routes - Root OIDC endpoints (default provider)
	r.Get("/.well-known/openid-configuration", handlers.Discovery)
	r.Get("/.well-known/jwks.json", handlers.JWKS)
	r.Get("/authorize", handlers.Authorize)
	r.Post("/token", handlers.Token)

	// Userinfo with rate limiting
	r.With(appMiddleware.RateLimit(userinfoRateLimiter)).Get("/userinfo", handlers.Userinfo)

	// Provider-scoped OIDC endpoints
	// Each provider has its own issuer: {base_issuer}/providers/{provider_name}
	r.Get("/providers/{provider}/.well-known/openid-configuration", handlers.ProviderDiscovery)
	r.Get("/providers/{provider}/authorize", handlers.ProviderAuthorize)
	r.Post("/providers/{provider}/token", handlers.ProviderToken)
	r.With(appMiddleware.RateLimit(userinfoRateLimiter)).Get("/providers/{provider}/userinfo", handlers.ProviderUserinfo)

	// OAuth provider routes - dynamic based on registered providers
	r.Get("/auth/{provider}", handlers.OAuthStart)
	r.Get("/auth/{provider}/callback", handlers.OAuthCallback)

	// Debug routes (conditional)
	if cfg.DebugEnabled {
		r.Get("/debug/login", handlers.DebugLogin)
		r.Get("/debug/callback", handlers.DebugCallback)
	}

	// Health check
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Create server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan struct{})
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh

		logger.Info("shutting down server...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			logger.Error("server shutdown error", "error", err)
		}

		close(done)
	}()

	logger.Info("starting server", "port", cfg.Port)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}

	<-done
	logger.Info("server stopped")

	return nil
}
