package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// UserinfoResponse represents the userinfo endpoint response.
type UserinfoResponse struct {
	Sub               string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

// extractBearerToken extracts the bearer token from the Authorization header.
// Returns empty string and sends error response if invalid.
func (h *Handlers) extractBearerToken(w http.ResponseWriter, r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.userinfoError(w, http.StatusUnauthorized, "invalid_token", "Missing Authorization header")
		return ""
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		h.userinfoError(w, http.StatusUnauthorized, "invalid_token", "Invalid Authorization header format")
		return ""
	}

	return strings.TrimPrefix(authHeader, "Bearer ")
}

// buildUserinfoResponse builds the userinfo response from token claims.
func buildUserinfoResponse(token jwt.Token) UserinfoResponse {
	resp := UserinfoResponse{
		Sub: token.Subject(),
	}

	// Get additional claims if present
	if name, ok := token.Get("name"); ok {
		if nameStr, ok := name.(string); ok {
			resp.Name = nameStr
		}
	}
	if username, ok := token.Get("preferred_username"); ok {
		if usernameStr, ok := username.(string); ok {
			resp.PreferredUsername = usernameStr
		}
	}
	if email, ok := token.Get("email"); ok {
		if emailStr, ok := email.(string); ok {
			resp.Email = emailStr
		}
	}
	if emailVerified, ok := token.Get("email_verified"); ok {
		if emailVerifiedBool, ok := emailVerified.(bool); ok {
			resp.EmailVerified = emailVerifiedBool
		}
	}
	if picture, ok := token.Get("picture"); ok {
		if pictureStr, ok := picture.(string); ok {
			resp.Picture = pictureStr
		}
	}

	return resp
}

// handleUserinfo processes the userinfo request logic shared by Userinfo and ProviderUserinfo.
// expectedIssuer is optional - if provided, validates that the token was issued with this issuer.
func (h *Handlers) handleUserinfo(w http.ResponseWriter, r *http.Request, expectedIssuer string) {
	tokenString := h.extractBearerToken(w, r)
	if tokenString == "" {
		return // Error already sent
	}

	// Parse and validate the access token
	token, err := h.tokenService.ParseAccessToken(tokenString)
	if err != nil {
		h.logger.Debug("failed to parse access token", "error", err)
		h.userinfoError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired token")
		return
	}

	// Validate issuer if expected (provider-scoped endpoint)
	if expectedIssuer != "" && token.Issuer() != expectedIssuer {
		h.userinfoError(w, http.StatusUnauthorized, "invalid_token", "Token was not issued for this provider")
		return
	}

	// Build and return userinfo response
	resp := buildUserinfoResponse(token)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("failed to encode userinfo response", "error", err)
	}
}

// Userinfo handles GET /userinfo.
// This returns user claims based on the access token.
func (h *Handlers) Userinfo(w http.ResponseWriter, r *http.Request) {
	h.handleUserinfo(w, r, "")
}

// ProviderUserinfo handles GET /providers/{provider}/userinfo.
// This is the provider-scoped userinfo endpoint.
// It validates that the token was issued with this provider's issuer.
func (h *Handlers) ProviderUserinfo(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	// Validate provider exists
	if h.providerRegistry.Get(providerName) == nil {
		http.Error(w, "Unknown provider", http.StatusNotFound)
		return
	}

	expectedIssuer := h.cfg.ProviderIssuer(providerName)
	h.handleUserinfo(w, r, expectedIssuer)
}

// userinfoError sends an error response for the userinfo endpoint.
func (h *Handlers) userinfoError(w http.ResponseWriter, status int, errorCode, errorDescription string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+errorCode+`", error_description="`+errorDescription+`"`)
	w.WriteHeader(status)
}
