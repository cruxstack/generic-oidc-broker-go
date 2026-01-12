package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/cruxstack/generic-oidc-broker/internal/service"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
	"github.com/go-chi/chi/v5"
)

// TokenRequest represents the token endpoint request.
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// TokenResponse represents the token endpoint response.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

// TokenErrorResponse represents a token endpoint error.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// tokenParams holds parsed token request parameters.
type tokenParams struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
}

// parseTokenParams extracts token request parameters from form data and auth header.
func (h *Handlers) parseTokenParams(r *http.Request) (*tokenParams, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	params := &tokenParams{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
	}

	// Check for Basic auth if credentials not in form
	if params.ClientID == "" || params.ClientSecret == "" {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Basic ") {
			decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					params.ClientID = parts[0]
					params.ClientSecret = parts[1]
				}
			}
		}
	}

	return params, nil
}

// handleTokenExchange processes the token exchange logic shared by Token and ProviderToken.
// expectedIssuer is optional - if provided, validates that the auth code was issued for this issuer.
func (h *Handlers) handleTokenExchange(w http.ResponseWriter, r *http.Request, expectedIssuer string) {
	params, err := h.parseTokenParams(r)
	if err != nil {
		h.tokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request body")
		return
	}

	// Validate grant type
	if params.GrantType != "authorization_code" {
		h.tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Only authorization_code grant type is supported")
		return
	}

	// Validate required parameters
	if params.Code == "" {
		h.tokenError(w, http.StatusBadRequest, "invalid_request", "Missing code parameter")
		return
	}

	if params.ClientID == "" {
		h.tokenError(w, http.StatusBadRequest, "invalid_request", "Missing client_id parameter")
		return
	}

	// Validate client credentials
	if !h.clientService.ValidateClient(params.ClientID, params.ClientSecret) {
		h.tokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// Get authorization code data
	codeData, err := h.authCodeStore.Get(params.Code)
	if err != nil {
		h.logger.Error("failed to get auth code", "error", err)
		h.tokenError(w, http.StatusInternalServerError, "server_error", "Internal server error")
		return
	}

	if codeData == nil {
		h.tokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired authorization code")
		return
	}

	// Validate issuer if expected (provider-scoped endpoint)
	if expectedIssuer != "" && codeData.Issuer != expectedIssuer {
		h.tokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code was not issued for this provider")
		return
	}

	// Validate client ID matches
	if codeData.ClientID != params.ClientID {
		h.tokenError(w, http.StatusBadRequest, "invalid_grant", "Client ID mismatch")
		return
	}

	// Validate redirect URI matches (if provided)
	if params.RedirectURI != "" && codeData.RedirectURI != params.RedirectURI {
		h.tokenError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch")
		return
	}

	// Create tokens
	idToken, accessToken, err := h.createTokens(codeData, params.ClientID)
	if err != nil {
		h.logger.Error("failed to create tokens", "error", err)
		h.tokenError(w, http.StatusInternalServerError, "server_error", "Failed to create tokens")
		return
	}

	// Return token response
	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   AccessTokenExpiresInSeconds,
		IDToken:     idToken,
		Scope:       codeData.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode token response", "error", err)
	}
}

// createTokens creates ID and access tokens from authorization code data.
func (h *Handlers) createTokens(codeData *store.AuthCodeData, clientID string) (idToken, accessToken string, err error) {
	// Determine if subject should be prefixed based on provider config
	prefixSubject := false
	if p := h.providerRegistry.Get(codeData.UserData.Provider); p != nil {
		prefixSubject = p.PrefixSubject()
	}

	// Create ID token
	idToken, err = h.tokenService.CreateIDToken(&service.IDTokenClaims{
		Subject:         codeData.UserData.Subject(prefixSubject),
		Name:            codeData.UserData.Name,
		PreferredUser:   codeData.UserData.Username,
		Email:           codeData.UserData.Email,
		EmailVerified:   codeData.UserData.EmailVerified,
		ProfileImageURL: codeData.UserData.ProfileImageURL,
		ClientID:        clientID,
		Nonce:           codeData.Nonce,
		Issuer:          codeData.Issuer,
	})
	if err != nil {
		return "", "", err
	}

	// Create access token
	accessToken, err = h.tokenService.CreateAccessToken(&service.AccessTokenClaims{
		Subject:  codeData.UserData.Subject(prefixSubject),
		ClientID: clientID,
		Scope:    codeData.Scope,
		Issuer:   codeData.Issuer,
	})
	if err != nil {
		return "", "", err
	}

	return idToken, accessToken, nil
}

// ProviderToken handles POST /providers/{provider}/token.
// This is the provider-scoped OIDC token endpoint.
// It validates that the auth code was issued for this provider-scoped issuer.
func (h *Handlers) ProviderToken(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	// Validate provider exists
	if h.providerRegistry.Get(providerName) == nil {
		h.tokenError(w, http.StatusNotFound, "invalid_request", "Unknown provider")
		return
	}

	expectedIssuer := h.cfg.ProviderIssuer(providerName)
	h.handleTokenExchange(w, r, expectedIssuer)
}

// tokenError sends a JSON error response for the token endpoint.
func (h *Handlers) tokenError(w http.ResponseWriter, status int, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
	}); err != nil {
		h.logger.Error("failed to encode token error response", "error", err)
	}
}
