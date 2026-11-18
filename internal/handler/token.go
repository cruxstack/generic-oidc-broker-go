package handler

import (
	"crypto/subtle"
	"errors"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/middleware"
	"github.com/cruxstack/generic-oidc-broker/internal/store"
	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

// tokenResponse is a successful token response (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// tokenErrorResponse is an error response from the token endpoint
// (RFC 6749 §5.2).
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// Token handles POST /providers/{provider}/token. Only the
// authorization_code grant is supported.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if err := r.ParseForm(); err != nil {
		h.tokenError(w, http.StatusBadRequest, "invalid_request", "malformed request body")
		return
	}

	client, ok := h.authenticateTokenRequest(w, r)
	if !ok {
		return
	}

	switch grantType := r.PostForm.Get("grant_type"); grantType {
	case "authorization_code":
	case "":
		h.tokenError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	default:
		h.tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only the authorization_code grant is supported")
		return
	}

	code, redirectURI := r.PostForm.Get("code"), r.PostForm.Get("redirect_uri")
	if code == "" || redirectURI == "" {
		h.tokenError(w, http.StatusBadRequest, "invalid_request", "code and redirect_uri are required")
		return
	}

	data, err := h.codes.Consume(r.Context(), code)
	if errors.Is(err, store.ErrNotFound) {
		h.tokenError(w, http.StatusBadRequest, "invalid_grant", "the authorization code is invalid, expired or already used")
		return
	}
	if err != nil {
		h.logger.Error("reading authorization code", "error", err)
		h.tokenError(w, http.StatusInternalServerError, "server_error", "could not read the authorization code")
		return
	}
	if problem := checkRedemption(data, h.issuerFor(r), client.ClientID, redirectURI, r.PostForm.Get("code_verifier")); problem != "" {
		h.tokenError(w, http.StatusBadRequest, "invalid_grant", problem)
		return
	}

	resp, err := h.issueTokens(data)
	if err != nil {
		h.logger.Error("issuing tokens", "error", err)
		h.tokenError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
		return
	}
	h.writeJSON(w, http.StatusOK, resp)
}

// authenticateTokenRequest authenticates the client making a token request.
// On failure it writes the error response and returns false. Clients that
// fail repeatedly are locked out by IP address rather than client ID, so
// that an attacker can't lock out a legitimate client.
func (h *Handler) authenticateTokenRequest(w http.ResponseWriter, r *http.Request) (config.Client, bool) {
	ipKey := middleware.ClientKey(r)
	if blocked, retryAfter := h.authFailures.Blocked(ipKey); blocked {
		middleware.SetRetryAfter(w, retryAfter)
		h.tokenError(w, http.StatusTooManyRequests, "invalid_client", "too many failed client authentications; try again later")
		return config.Client{}, false
	}

	creds, err := readClientCredentials(r)
	if err != nil && !errors.Is(err, errNoClientAuth) {
		h.tokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return config.Client{}, false
	}
	client, ok := h.authenticateClient(creds)
	if err != nil || !ok {
		h.authFailures.Record(ipKey)
		if creds.basic {
			w.Header().Set("WWW-Authenticate", `Basic realm="oidc-broker"`)
		}
		h.tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return config.Client{}, false
	}
	return client, true
}

// checkRedemption returns why code may not be redeemed by this request, or
// "" if it may.
func checkRedemption(code store.AuthCode, issuer, clientID, redirectURI, verifier string) string {
	switch {
	case code.Issuer != issuer:
		return "the authorization code was issued by a different provider"
	case code.ClientID != clientID:
		return "the authorization code was issued to a different client"
	case code.RedirectURI != redirectURI:
		return "redirect_uri does not match the authorization request"
	case !verifyPKCE(code.CodeChallenge, verifier):
		return "code_verifier is missing or does not match the code_challenge"
	}
	return ""
}

// verifyPKCE checks an RFC 7636 S256 code verifier against the challenge from
// the authorization request. Without a challenge there must be no verifier,
// which prevents PKCE downgrade attacks (RFC 9700 §2.1.1).
func verifyPKCE(challenge, verifier string) bool {
	if challenge == "" {
		return verifier == ""
	}
	computed := oauth2.S256ChallengeFromVerifier(verifier)
	return verifier != "" && subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// issueTokens signs the ID and access tokens for a redeemed code.
func (h *Handler) issueTokens(code store.AuthCode) (tokenResponse, error) {
	idToken, err := h.tokens.SignIDToken(token.IDToken{
		Issuer:   code.Issuer,
		ClientID: code.ClientID,
		Identity: code.Identity,
		Nonce:    code.Nonce,
	})
	if err != nil {
		return tokenResponse{}, err
	}
	accessToken, err := h.tokens.SignAccessToken(token.AccessToken{
		Issuer:   code.Issuer,
		ClientID: code.ClientID,
		Scope:    code.Scope,
		Identity: code.Identity,
	})
	if err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(token.AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       code.Scope,
	}, nil
}

func (h *Handler) tokenError(w http.ResponseWriter, status int, code, description string) {
	h.writeJSON(w, status, tokenErrorResponse{Error: code, ErrorDescription: description})
}
