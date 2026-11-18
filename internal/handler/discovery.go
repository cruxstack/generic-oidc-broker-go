package handler

import "net/http"

// metadataCacheControl lets clients cache discovery metadata and keys, while
// still picking up a rotated signing key within minutes.
const metadataCacheControl = "public, max-age=300"

// discoveryDocument is the OpenID Provider metadata (OIDC Discovery §3).
type discoveryDocument struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                            []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// Discovery handles GET /providers/{provider}/.well-known/openid-configuration.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	issuer := h.issuerFor(r)
	w.Header().Set("Cache-Control", metadataCacheControl)
	h.writeJSON(w, http.StatusOK, discoveryDocument{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     issuer + "/token",
		UserinfoEndpoint:                  issuer + "/userinfo",
		JWKSURI:                           issuer + "/.well-known/jwks.json",
		ResponseTypesSupported:            []string{"code", "id_token", "code id_token"},
		ResponseModesSupported:            []string{"query", "fragment"},
		GrantTypesSupported:               []string{"authorization_code", "implicit"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   supportedScopes,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported: []string{
			"iss", "sub", "aud", "exp", "iat", "jti", "nonce", "c_hash",
			"name", "preferred_username", "picture", "email", "email_verified",
		},
		AuthorizationResponseIssParameterSupported: true,
	})
}

// JWKS handles GET /providers/{provider}/.well-known/jwks.json.
func (h *Handler) JWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", metadataCacheControl)
	h.writeJSON(w, http.StatusOK, h.tokens.JWKS())
}
