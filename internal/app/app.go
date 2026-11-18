// Package app assembles the broker from its configuration. The broker
// binary and the end-to-end tests both build the server through New, so the
// tests exercise the production routing and middleware.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/handler"
	"github.com/cruxstack/generic-oidc-broker/internal/middleware"
	"github.com/cruxstack/generic-oidc-broker/internal/provider"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

const (
	// providerRequestTimeout bounds each request to an upstream provider.
	providerRequestTimeout = 10 * time.Second

	userinfoRateLimit       = 100
	userinfoRateLimitWindow = 15 * time.Minute
)

// App is an assembled broker.
type App struct {
	// Handler serves all of the broker's endpoints.
	Handler http.Handler
	codes   store.AuthCodes
}

// New validates cfg and builds the broker.
func New(ctx context.Context, cfg *config.Config, logger *slog.Logger) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	providers, err := provider.NewRegistry(cfg.Providers, &http.Client{Timeout: providerRequestTimeout})
	if err != nil {
		return nil, err
	}
	var previousKeys []token.Key
	if cfg.PreviousKeyID != "" {
		previousKeys = append(previousKeys, token.Key{ID: cfg.PreviousKeyID, PEM: cfg.PreviousKeyPEM})
	}
	tokens, err := token.NewService(token.Key{ID: cfg.SigningKeyID, PEM: cfg.SigningKeyPEM}, previousKeys...)
	if err != nil {
		return nil, err
	}
	codes, err := newAuthCodeStore(ctx, cfg)
	if err != nil {
		return nil, err
	}
	h, err := handler.New(cfg, providers, tokens, codes, logger)
	if err != nil {
		_ = codes.Close()
		return nil, err
	}

	return &App{Handler: newRouter(cfg, h, logger), codes: codes}, nil
}

// Close releases the broker's resources.
func (a *App) Close() error {
	return a.codes.Close()
}

func newAuthCodeStore(ctx context.Context, cfg *config.Config) (store.AuthCodes, error) {
	if !cfg.AuthCodeStore.UseRedis {
		return store.NewMemory(), nil
	}
	return store.NewRedis(ctx, cfg.Redis, cfg.AuthCodeStore.RedisKeyPrefix)
}

func newRouter(cfg *config.Config, h *handler.Handler, logger *slog.Logger) http.Handler {
	r := chi.NewRouter()
	r.Use(
		chimw.RequestID,
		clientIPMiddleware(cfg.ClientIP),
		middleware.RequestLogger(logger),
		chimw.Recoverer,
		middleware.SecureHeaders,
	)

	r.Get("/health", h.Health)

	userinfoLimit := middleware.RateLimitByIP(middleware.NewLimiter(userinfoRateLimit, userinfoRateLimitWindow))
	r.Route("/providers/{provider}", func(r chi.Router) {
		r.Use(h.WithProvider)
		r.Get("/.well-known/openid-configuration", h.Discovery)
		r.Get("/.well-known/jwks.json", h.JWKS)
		r.Get("/authorize", h.Authorize)
		r.Post("/token", h.Token)
		r.With(userinfoLimit).Get("/userinfo", h.Userinfo)
		r.With(userinfoLimit).Post("/userinfo", h.Userinfo)
	})
	r.With(h.WithProvider).Get("/auth/{provider}/callback", h.Callback)

	if cfg.Debug.Enabled {
		r.Get("/debug/login", h.DebugLogin)
		r.Get("/debug/callback", h.DebugCallback)
	}
	return r
}

// clientIPMiddleware selects how the client's IP address is determined.
// Proxy headers are only trusted when configured, since clients that reach
// the broker directly can set them to anything.
func clientIPMiddleware(c config.ClientIP) func(http.Handler) http.Handler {
	switch {
	case c.TrustedProxyCount > 0:
		return chimw.ClientIPFromXFFTrustedProxies(c.TrustedProxyCount)
	case c.Header != "":
		return chimw.ClientIPFromHeader(c.Header, c.TrustedProxyCIDRs...)
	case len(c.TrustedProxyCIDRs) > 0:
		return chimw.ClientIPFromXFF(c.TrustedProxyCIDRs...)
	default:
		return chimw.ClientIPFromRemoteAddr
	}
}
