package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// DiscoveryDocument represents the OIDC discovery document.
type DiscoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

// buildDiscoveryDocument creates a discovery document for the given issuer.
// If jwksIssuer is provided, it's used for the JWKS URI; otherwise issuer is used.
func buildDiscoveryDocument(issuer, jwksIssuer string) DiscoveryDocument {
	if jwksIssuer == "" {
		jwksIssuer = issuer
	}

	return DiscoveryDocument{
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		UserinfoEndpoint:      issuer + "/userinfo",
		JwksURI:               jwksIssuer + "/.well-known/jwks.json",
		ResponseTypesSupported: []string{
			"code",
			"id_token",
			"token id_token",
			"id_token token",
			"code id_token",
		},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
		},
		ClaimsSupported: []string{
			"sub",
			"name",
			"preferred_username",
			"email",
			"email_verified",
			"picture",
			"iss",
			"aud",
			"exp",
			"iat",
			"nonce",
		},
	}
}

// Discovery handles GET /.well-known/openid-configuration.
func (h *Handlers) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := buildDiscoveryDocument(h.cfg.OIDCIssuer, "")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		h.logger.Error("failed to encode discovery document", "error", err)
	}
}

// ProviderDiscovery handles GET /providers/{provider}/.well-known/openid-configuration.
// Returns a provider-scoped discovery document with provider-specific issuer and endpoints.
func (h *Handlers) ProviderDiscovery(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	// Validate provider exists
	if h.providerRegistry.Get(providerName) == nil {
		http.Error(w, "Unknown provider", http.StatusNotFound)
		return
	}

	issuer := h.cfg.ProviderIssuer(providerName)
	// Use provider-scoped JWKS URI for consistency
	doc := buildDiscoveryDocument(issuer, "")

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(doc); err != nil {
		h.logger.Error("failed to encode discovery document", "error", err)
	}
}
