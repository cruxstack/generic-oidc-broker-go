// Package handler implements the broker's HTTP endpoints.
//
// Every configured provider is exposed as its own OIDC issuer at
// /providers/{provider}. A sign-in runs as follows:
//
//  1. The client sends the user to /providers/{provider}/authorize. The
//     request is validated and kept in an encrypted cookie, and the user is
//     redirected to the upstream provider.
//  2. The provider returns the user to /auth/{provider}/callback. The broker
//     redeems the provider's code for the user's profile and redirects the
//     user back to the client with an authorization code and/or ID token.
//  3. The client redeems its code at /providers/{provider}/token and may call
//     /providers/{provider}/userinfo with the access token.
package handler

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/middleware"
	"github.com/cruxstack/generic-oidc-broker/internal/provider"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

const (
	// upstreamTimeout bounds the requests made to an upstream provider while
	// completing a sign-in.
	upstreamTimeout = 20 * time.Second

	// Clients are locked out of the token endpoint for the rest of the window
	// after this many failed authentications.
	maxClientAuthFailures   = 10
	clientAuthFailureWindow = 15 * time.Minute
)

// Handler serves the broker's endpoints.
type Handler struct {
	cfg          *config.Config
	providers    *provider.Registry
	tokens       *token.Service
	codes        store.AuthCodes
	flows        *flowCookie
	authFailures *middleware.Limiter
	logger       *slog.Logger

	// debugClient makes the debug pages' requests to the token and userinfo
	// endpoints.
	debugClient *http.Client
}

// New returns a Handler. cfg must be valid.
func New(cfg *config.Config, providers *provider.Registry, tokens *token.Service, codes store.AuthCodes, logger *slog.Logger) (*Handler, error) {
	flows, err := newFlowCookie(cfg.SessionSecret, cfg.SessionSecureCookie)
	if err != nil {
		return nil, err
	}
	return &Handler{
		cfg:          cfg,
		providers:    providers,
		tokens:       tokens,
		codes:        codes,
		flows:        flows,
		authFailures: middleware.NewLimiter(maxClientAuthFailures, clientAuthFailureWindow),
		logger:       logger,
		debugClient:  &http.Client{Timeout: 10 * time.Second},
	}, nil
}

// Health handles GET /health.
func (h *Handler) Health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok"))
}

type providerContextKey struct{}

// WithProvider resolves the {provider} URL parameter and responds 404 for
// providers that are not configured.
func (h *Handler) WithProvider(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := h.providers.Get(chi.URLParam(r, "provider"))
		if p == nil {
			http.Error(w, "Unknown provider", http.StatusNotFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), providerContextKey{}, p)))
	})
}

// providerFrom returns the provider resolved by WithProvider.
func providerFrom(r *http.Request) *provider.Provider {
	return r.Context().Value(providerContextKey{}).(*provider.Provider)
}

// issuerFor returns the OIDC issuer of the request's provider.
func (h *Handler) issuerFor(r *http.Request) string {
	return h.cfg.ProviderIssuer(providerFrom(r).Name())
}

// writeJSON writes v as a JSON response.
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		h.logger.Error("writing JSON response", "error", err)
	}
}

// renderError shows an error page to the user. It is used when an error
// cannot safely be returned to the client's redirect URI.
func renderError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, message, status)
}
