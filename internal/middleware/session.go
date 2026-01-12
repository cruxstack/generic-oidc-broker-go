package middleware

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// SessionKey is the context key for the session.
type sessionContextKey struct{}

// SessionName is the name of the session cookie.
const SessionName = "oidc-broker-session"

// Session data keys (using snake_case for consistency).
const (
	SessionKeyCodeVerifier = "code_verifier"
	SessionKeyRedirectURI  = "redirect_uri"
	SessionKeyState        = "state"
	SessionKeyNonce        = "nonce"
	SessionKeyClientID     = "client_id"
	SessionKeyResponseType = "response_type"
	SessionKeyScope        = "scope"
	SessionKeyIssuer       = "issuer" // Provider-scoped issuer override
)

// SessionMaxAge is the maximum age of a session cookie (24 hours).
const SessionMaxAge = 86400

// NewSessionStore creates a new session store based on configuration.
func NewSessionStore(cfg *config.Config) (sessions.Store, error) {
	// For now, use cookie store. Redis store can be added later.
	store := sessions.NewCookieStore([]byte(cfg.SessionSecret))

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   SessionMaxAge,
		HttpOnly: true,
		Secure:   cfg.SessionSecureCookie,
		SameSite: http.SameSiteLaxMode,
	}

	return store, nil
}

// Session returns a middleware that manages sessions.
func Session(store sessions.Store, cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session, _ := store.Get(r, SessionName)
			ctx := context.WithValue(r.Context(), sessionContextKey{}, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetSession retrieves the session from the request context.
func GetSession(r *http.Request) *sessions.Session {
	session, ok := r.Context().Value(sessionContextKey{}).(*sessions.Session)
	if !ok {
		return nil
	}
	return session
}

// SaveSession saves the session to the response.
func SaveSession(r *http.Request, w http.ResponseWriter) error {
	session := GetSession(r)
	if session == nil {
		return nil
	}
	return session.Save(r, w)
}
