package handler

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/cruxstack/generic-oidc-broker/internal/middleware"
	"github.com/go-chi/chi/v5"
)

// authorizeParams holds parsed authorization request parameters.
type authorizeParams struct {
	ClientID     string
	RedirectURI  string
	ResponseType string
	State        string
	Nonce        string
	Scope        string
}

// parseAuthorizeParams extracts and validates common authorization parameters.
func (h *Handlers) parseAuthorizeParams(r *http.Request) *authorizeParams {
	return &authorizeParams{
		ClientID:     r.URL.Query().Get("client_id"),
		RedirectURI:  r.URL.Query().Get("redirect_uri"),
		ResponseType: r.URL.Query().Get("response_type"),
		State:        r.URL.Query().Get("state"),
		Nonce:        r.URL.Query().Get("nonce"),
		Scope:        r.URL.Query().Get("scope"),
	}
}

// validateAuthorizeParams validates authorization parameters and returns an error response if invalid.
// Returns true if validation passed, false if an error response was sent.
func (h *Handlers) validateAuthorizeParams(w http.ResponseWriter, r *http.Request, params *authorizeParams) bool {
	// Validate required parameters
	if params.ClientID == "" {
		h.authorizeError(w, r, params.RedirectURI, params.State, "invalid_request", "Missing client_id parameter")
		return false
	}

	if params.RedirectURI == "" {
		h.authorizeError(w, r, "", params.State, "invalid_request", "Missing redirect_uri parameter")
		return false
	}

	if params.ResponseType == "" {
		h.authorizeError(w, r, params.RedirectURI, params.State, "invalid_request", "Missing response_type parameter")
		return false
	}

	// Validate client
	client := h.clientService.GetClient(params.ClientID)
	if client == nil {
		h.authorizeError(w, r, params.RedirectURI, params.State, "unauthorized_client", "Unknown client")
		return false
	}

	// Validate redirect URI
	if !h.clientService.ValidateRedirectURI(params.ClientID, params.RedirectURI) {
		h.authorizeError(w, r, "", params.State, "invalid_request", "Invalid redirect_uri")
		return false
	}

	// Validate response type
	if !validResponseTypes[params.ResponseType] {
		h.authorizeError(w, r, params.RedirectURI, params.State, "unsupported_response_type", "Unsupported response_type")
		return false
	}

	return true
}

// storeAuthorizeSession stores authorization parameters in the session.
func (h *Handlers) storeAuthorizeSession(r *http.Request, w http.ResponseWriter, params *authorizeParams, issuer string) {
	session := middleware.GetSession(r)
	if session != nil {
		session.Values[middleware.SessionKeyClientID] = params.ClientID
		session.Values[middleware.SessionKeyRedirectURI] = params.RedirectURI
		session.Values[middleware.SessionKeyResponseType] = params.ResponseType
		session.Values[middleware.SessionKeyState] = params.State
		session.Values[middleware.SessionKeyNonce] = params.Nonce
		session.Values[middleware.SessionKeyScope] = params.Scope
		if issuer != "" {
			session.Values[middleware.SessionKeyIssuer] = issuer
		}
		if err := middleware.SaveSession(r, w); err != nil {
			h.logger.Error("failed to save session", "error", err)
		}
	}
}

// Authorize handles GET /authorize.
// This is the OIDC authorization endpoint that uses the first configured provider.
// For provider-specific authorization, use /providers/{provider}/authorize instead.
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	params := h.parseAuthorizeParams(r)

	if !h.validateAuthorizeParams(w, r, params) {
		return
	}

	// Use first configured provider
	availableProviders := h.providerRegistry.List()
	if len(availableProviders) == 0 {
		h.authorizeError(w, r, params.RedirectURI, params.State, "server_error", "No OAuth providers configured")
		return
	}
	providerName := availableProviders[0]

	// Store authorization parameters in session (no custom issuer for root endpoint)
	h.storeAuthorizeSession(r, w, params, "")

	// Redirect to OAuth provider authentication
	http.Redirect(w, r, "/auth/"+providerName, http.StatusFound)
}

// ProviderAuthorize handles GET /providers/{provider}/authorize.
// This is the provider-scoped OIDC authorization endpoint.
func (h *Handlers) ProviderAuthorize(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	// Validate provider exists
	if h.providerRegistry.Get(providerName) == nil {
		http.Error(w, "Unknown provider", http.StatusNotFound)
		return
	}

	params := h.parseAuthorizeParams(r)

	if !h.validateAuthorizeParams(w, r, params) {
		return
	}

	// Store authorization parameters in session with provider-scoped issuer
	h.storeAuthorizeSession(r, w, params, h.cfg.ProviderIssuer(providerName))

	// Redirect to OAuth provider authentication
	http.Redirect(w, r, "/auth/"+providerName, http.StatusFound)
}

// authorizeError sends an error response for the authorize endpoint.
func (h *Handlers) authorizeError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, errorDescription string) {
	// If we have a valid redirect URI, redirect with error parameters
	if redirectURI != "" {
		u, err := url.Parse(redirectURI)
		if err == nil {
			q := u.Query()
			q.Set("error", errorCode)
			q.Set("error_description", errorDescription)
			if state != "" {
				q.Set("state", state)
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}

	// Otherwise, return an error page
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusBadRequest)
	if _, err := w.Write([]byte(errorCode + ": " + errorDescription)); err != nil {
		h.logger.Error("failed to write error response", "error", err)
	}
}

// buildRedirectURL constructs the redirect URL with authorization response parameters.
func buildRedirectURL(baseURI, responseType, code, idToken, accessToken, state string) (string, error) {
	u, err := url.Parse(baseURI)
	if err != nil {
		return "", err
	}

	// Determine if we should use fragment or query parameters
	// Fragment is used for implicit flow (id_token, token)
	useFragment := strings.Contains(responseType, "id_token") ||
		(strings.Contains(responseType, "token") && !strings.Contains(responseType, "code"))

	params := url.Values{}
	if code != "" {
		params.Set("code", code)
	}
	if idToken != "" {
		params.Set("id_token", idToken)
	}
	if accessToken != "" {
		params.Set("access_token", accessToken)
		params.Set("token_type", "Bearer")
		params.Set("expires_in", "3600")
	}
	if state != "" {
		params.Set("state", state)
	}

	if useFragment {
		u.Fragment = params.Encode()
	} else {
		u.RawQuery = params.Encode()
	}

	return u.String(), nil
}
