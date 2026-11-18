package handler

import (
	"net/http"
	"strings"
)

// Userinfo handles GET and POST /providers/{provider}/userinfo (OIDC Core
// §5.3). It returns the claims of the user the access token was issued for.
func (h *Handler) Userinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	raw, ok := bearerToken(r)
	if !ok {
		// RFC 6750 §3.1: requests without credentials get no error code.
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc-broker"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	accessToken, err := h.tokens.VerifyAccessToken(raw, h.issuerFor(r))
	if err != nil {
		h.logger.Debug("rejected access token", "error", err)
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="oidc-broker", error="invalid_token", error_description="The access token is invalid or expired"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	h.writeJSON(w, http.StatusOK, accessToken.Identity.Claims())
}

// bearerToken returns the token from an "Authorization: Bearer" header. The
// scheme is case-insensitive (RFC 9110 §11.1).
func bearerToken(r *http.Request) (string, bool) {
	scheme, credentials, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	credentials = strings.TrimSpace(credentials)
	if !ok || !strings.EqualFold(scheme, "Bearer") || credentials == "" {
		return "", false
	}
	return credentials, true
}
