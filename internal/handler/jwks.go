package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// JWKS handles GET /.well-known/jwks.json.
func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.tokenService.GetJWKS()); err != nil {
		h.logger.Error("failed to encode JWKS", "error", err)
	}
}

// ProviderJWKS handles GET /providers/{provider}/.well-known/jwks.json.
// Returns the same JWKS as the root endpoint (same signing key for all providers).
func (h *Handlers) ProviderJWKS(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	// Verify provider exists
	if h.cfg.GetProviderConfig(providerName) == nil {
		http.Error(w, "provider not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.tokenService.GetJWKS()); err != nil {
		h.logger.Error("failed to encode JWKS", "error", err)
	}
}
