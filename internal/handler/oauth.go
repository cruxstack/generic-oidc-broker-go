package handler

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/cruxstack/generic-oidc-broker/internal/crypto"
	"github.com/cruxstack/generic-oidc-broker/internal/middleware"
	"github.com/cruxstack/generic-oidc-broker/internal/service"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
)

// Session keys for OAuth flow
const (
	sessionKeyProviderName  = "oauth_provider"
	sessionKeyProviderState = "oauth_state"
)

// OAuthStart handles GET /auth/{provider}.
// This initiates the OAuth 2.0 flow for the specified provider.
func (h *Handlers) OAuthStart(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	if providerName == "" {
		http.Error(w, "Provider not specified", http.StatusBadRequest)
		return
	}

	// Get provider from registry
	p := h.providerRegistry.Get(providerName)
	if p == nil {
		http.Error(w, "Unknown provider: "+providerName, http.StatusNotFound)
		return
	}

	// Generate PKCE codes (even if provider doesn't support it, we'll just not use them)
	codeVerifier, codeChallenge, err := crypto.GeneratePKCECodes()
	if err != nil {
		h.logger.Error("failed to generate PKCE codes", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate state for CSRF protection
	state, err := crypto.GenerateRandomString(32)
	if err != nil {
		h.logger.Error("failed to generate state", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Store in session
	session := middleware.GetSession(r)
	if session != nil {
		session.Values[middleware.SessionKeyCodeVerifier] = codeVerifier
		session.Values[sessionKeyProviderState] = state
		session.Values[sessionKeyProviderName] = providerName
		middleware.SaveSession(r, w)
	}

	// Build authorization URL
	authURL := p.AuthURL(state, codeChallenge)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// OAuthCallback handles GET /auth/{provider}/callback.
// This handles the callback from the OAuth provider.
func (h *Handlers) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")
	if providerName == "" {
		http.Error(w, "Provider not specified", http.StatusBadRequest)
		return
	}

	// Get provider from registry
	p := h.providerRegistry.Get(providerName)
	if p == nil {
		http.Error(w, "Unknown provider: "+providerName, http.StatusNotFound)
		return
	}

	// Get query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// Check for error from provider
	if errorParam != "" {
		errorDesc := r.URL.Query().Get("error_description")
		h.logger.Error("OAuth error", "provider", providerName, "error", errorParam, "description", errorDesc)
		http.Error(w, "Authentication failed: "+errorDesc, http.StatusBadRequest)
		return
	}

	// Get session
	session := middleware.GetSession(r)
	if session == nil {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}

	// Validate state
	expectedState, _ := session.Values[sessionKeyProviderState].(string)
	if state != expectedState {
		h.logger.Error("state mismatch", "expected", expectedState, "got", state)
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Validate provider matches
	expectedProvider, _ := session.Values[sessionKeyProviderName].(string)
	if providerName != expectedProvider {
		h.logger.Error("provider mismatch", "expected", expectedProvider, "got", providerName)
		http.Error(w, "Provider mismatch", http.StatusBadRequest)
		return
	}

	// Get code verifier
	codeVerifier, _ := session.Values[middleware.SessionKeyCodeVerifier].(string)
	if codeVerifier == "" && p.SupportsPKCE() {
		http.Error(w, "Code verifier not found in session", http.StatusBadRequest)
		return
	}

	// Exchange code for access token
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	tokenResp, err := p.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		h.logger.Error("failed to exchange code", "provider", providerName, "error", err)
		http.Error(w, "Failed to exchange authorization code", http.StatusInternalServerError)
		return
	}

	// Get user info from provider
	userData, err := p.GetUser(ctx, tokenResp.AccessToken)
	if err != nil {
		h.logger.Error("failed to get user", "provider", providerName, "error", err)
		http.Error(w, "Failed to get user information", http.StatusInternalServerError)
		return
	}

	// Get OIDC parameters from session
	clientID, _ := session.Values[middleware.SessionKeyClientID].(string)
	redirectURI, _ := session.Values[middleware.SessionKeyRedirectURI].(string)
	responseType, _ := session.Values[middleware.SessionKeyResponseType].(string)
	oidcState, _ := session.Values[middleware.SessionKeyState].(string)
	nonce, _ := session.Values[middleware.SessionKeyNonce].(string)
	scope, _ := session.Values[middleware.SessionKeyScope].(string)
	issuer, _ := session.Values[middleware.SessionKeyIssuer].(string) // Provider-scoped issuer (may be empty)

	if redirectURI == "" {
		http.Error(w, "Missing redirect URI in session", http.StatusBadRequest)
		return
	}

	// Handle different response types
	var authCode, idToken, accessToken string

	// Generate authorization code if needed
	if strings.Contains(responseType, "code") {
		authCode, err = crypto.GenerateRandomString(32)
		if err != nil {
			h.logger.Error("failed to generate auth code", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Store authorization code
		err = h.authCodeStore.Store(authCode, &store.AuthCodeData{
			ClientID:    clientID,
			RedirectURI: redirectURI,
			Nonce:       nonce,
			UserData:    userData,
			Scope:       scope,
			Issuer:      issuer,
		})
		if err != nil {
			h.logger.Error("failed to store auth code", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Generate ID token if needed (implicit flow)
	if strings.Contains(responseType, "id_token") {
		idToken, err = h.tokenService.CreateIDToken(&service.IDTokenClaims{
			Subject:         userData.Subject(p.PrefixSubject()),
			Name:            userData.Name,
			PreferredUser:   userData.Username,
			Email:           userData.Email,
			EmailVerified:   userData.EmailVerified,
			ProfileImageURL: userData.ProfileImageURL,
			ClientID:        clientID,
			Nonce:           nonce,
			Issuer:          issuer,
		})
		if err != nil {
			h.logger.Error("failed to create ID token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Generate access token if needed (implicit flow with token)
	if strings.Contains(responseType, "token") && responseType != "code" {
		accessToken, err = h.tokenService.CreateAccessToken(&service.AccessTokenClaims{
			Subject:  userData.Subject(p.PrefixSubject()),
			ClientID: clientID,
			Scope:    scope,
			Issuer:   issuer,
		})
		if err != nil {
			h.logger.Error("failed to create access token", "error", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Build redirect URL
	redirectURL, err := buildRedirectURL(redirectURI, responseType, authCode, idToken, accessToken, oidcState)
	if err != nil {
		h.logger.Error("failed to build redirect URL", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Clear OIDC session data
	delete(session.Values, middleware.SessionKeyClientID)
	delete(session.Values, middleware.SessionKeyRedirectURI)
	delete(session.Values, middleware.SessionKeyResponseType)
	delete(session.Values, middleware.SessionKeyState)
	delete(session.Values, middleware.SessionKeyNonce)
	delete(session.Values, middleware.SessionKeyScope)
	delete(session.Values, middleware.SessionKeyIssuer)
	delete(session.Values, middleware.SessionKeyCodeVerifier)
	delete(session.Values, sessionKeyProviderState)
	delete(session.Values, sessionKeyProviderName)
	middleware.SaveSession(r, w)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
