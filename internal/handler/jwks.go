package handler

import (
	"encoding/json"
	"net/http"
)

// JWKS handles GET /.well-known/jwks.json.
func (h *Handlers) JWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.tokenService.GetJWKS()); err != nil {
		h.logger.Error("failed to encode JWKS", "error", err)
	}
}
