package handler

import (
	"log/slog"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/provider"
	"github.com/cruxstack/generic-oidc-broker/internal/service"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
)

// Handlers holds all HTTP handlers and their dependencies.
type Handlers struct {
	cfg              *config.Config
	tokenService     *service.TokenService
	clientService    *service.ClientService
	authCodeStore    store.AuthCodeStore
	providerRegistry *provider.Registry
	logger           *slog.Logger
}

// NewHandlers creates a new Handlers instance.
func NewHandlers(
	cfg *config.Config,
	tokenService *service.TokenService,
	clientService *service.ClientService,
	authCodeStore store.AuthCodeStore,
	providerRegistry *provider.Registry,
	logger *slog.Logger,
) *Handlers {
	return &Handlers{
		cfg:              cfg,
		tokenService:     tokenService,
		clientService:    clientService,
		authCodeStore:    authCodeStore,
		providerRegistry: providerRegistry,
		logger:           logger,
	}
}

// ProviderRegistry returns the provider registry for route setup.
func (h *Handlers) ProviderRegistry() *provider.Registry {
	return h.providerRegistry
}
