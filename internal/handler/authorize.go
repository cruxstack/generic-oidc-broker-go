package handler

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// maxParamLength bounds state and nonce, which are stored in the flow cookie.
const maxParamLength = 512

// supportedScopes are the scopes the broker understands. Others are ignored,
// as RFC 6749 §3.3 allows.
var supportedScopes = []string{"openid", "profile", "email"}

// responseType is a supported OIDC response_type: "code", "id_token" or
// "code id_token". Response types that return an access token from the
// authorization endpoint are not supported, following the OAuth 2.0
// Security Best Current Practice (RFC 9700 §2.1.2).
type responseType struct {
	Code    bool `json:"code"`
	IDToken bool `json:"id_token"`
}

// parseResponseType parses a space-separated response_type in any order.
func parseResponseType(raw string) (responseType, bool) {
	var rt responseType
	for value := range strings.FieldsSeq(raw) {
		switch {
		case value == "code" && !rt.Code:
			rt.Code = true
		case value == "id_token" && !rt.IDToken:
			rt.IDToken = true
		default:
			return responseType{}, false
		}
	}
	return rt, rt.Code || rt.IDToken
}

// authorizationRequest is a validated authorization request, kept in the
// flow cookie while the user signs in at the provider.
type authorizationRequest struct {
	Provider      string       `json:"provider"`
	ClientID      string       `json:"client_id"`
	RedirectURI   string       `json:"redirect_uri"`
	ResponseType  responseType `json:"response_type"`
	Scope         string       `json:"scope"`
	State         string       `json:"state,omitempty"`
	Nonce         string       `json:"nonce,omitempty"`
	CodeChallenge string       `json:"code_challenge,omitempty"`
	// ProviderVerifier is the PKCE verifier for the broker's own
	// authorization request to the provider.
	ProviderVerifier string    `json:"provider_verifier"`
	CreatedAt        time.Time `json:"created_at"`
}

// Authorize handles GET /providers/{provider}/authorize. It validates the
// client's request and sends the user to the provider to sign in.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	p := providerFrom(r)
	query := r.URL.Query()

	// Until the client and redirect URI are known to be valid, errors are
	// shown to the user and never redirected (RFC 6749 §4.1.2.1).
	client, ok := h.cfg.Client(query.Get("client_id"))
	if !ok {
		renderError(w, http.StatusBadRequest, "The client_id is missing or unknown.")
		return
	}
	redirectURI := query.Get("redirect_uri")
	if !client.AllowsRedirectURI(redirectURI) {
		renderError(w, http.StatusBadRequest, "The redirect_uri is missing or not registered for this client.")
		return
	}

	rt, ok := parseResponseType(query.Get("response_type"))
	reply := authorizationReply{
		redirectURI: redirectURI,
		state:       query.Get("state"),
		issuer:      h.issuerFor(r),
		fragment:    rt.IDToken,
	}
	if !ok {
		reply.sendError(w, r, "unsupported_response_type", "response_type must be code, id_token or code id_token")
		return
	}

	req := authorizationRequest{
		Provider:     p.Name(),
		ClientID:     client.ClientID,
		RedirectURI:  redirectURI,
		ResponseType: rt,
	}
	if err := readAuthorizationParams(query, &req); err != nil {
		reply.sendError(w, r, err.code, err.description)
		return
	}

	state, verifier := rand.Text(), oauth2.GenerateVerifier()
	req.ProviderVerifier = verifier
	req.CreatedAt = h.flows.now()
	if err := h.flows.add(w, r, state, req); err != nil {
		h.logger.Error("saving sign-in cookie", "error", err)
		reply.sendError(w, r, "server_error", "could not start sign-in")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.AuthCodeURL(state, verifier), http.StatusFound)
}

// readAuthorizationParams validates and copies the request parameters other
// than client_id, redirect_uri and response_type into req.
func readAuthorizationParams(query url.Values, req *authorizationRequest) *oauthError {
	scope, ok := normalizeScope(query.Get("scope"))
	if !ok {
		return &oauthError{"invalid_scope", "scope must include openid"}
	}
	req.Scope = scope

	req.State, req.Nonce = query.Get("state"), query.Get("nonce")
	if len(req.State) > maxParamLength || len(req.Nonce) > maxParamLength {
		return &oauthError{"invalid_request", "state and nonce must be at most 512 characters"}
	}
	// OIDC Core §3.2.2.1 and §3.3.2.11.
	if req.ResponseType.IDToken && req.Nonce == "" {
		return &oauthError{"invalid_request", "nonce is required when response_type includes id_token"}
	}

	challenge, method := query.Get("code_challenge"), query.Get("code_challenge_method")
	switch {
	case challenge == "" && method == "":
		// The client is not using PKCE.
	case challenge == "":
		return &oauthError{"invalid_request", "code_challenge_method requires code_challenge"}
	case method != "S256":
		return &oauthError{"invalid_request", "code_challenge_method must be S256"}
	case !isS256Challenge(challenge):
		return &oauthError{"invalid_request", "code_challenge must be a base64url-encoded SHA-256 hash"}
	}
	req.CodeChallenge = challenge
	return nil
}

// normalizeScope keeps the supported scopes in the order requested, without
// duplicates, and reports whether openid is among them.
func normalizeScope(raw string) (string, bool) {
	var kept []string
	for scope := range strings.FieldsSeq(raw) {
		if slices.Contains(supportedScopes, scope) && !slices.Contains(kept, scope) {
			kept = append(kept, scope)
		}
	}
	return strings.Join(kept, " "), slices.Contains(kept, "openid")
}

// isS256Challenge reports whether challenge has the form of an RFC 7636 S256
// code challenge: an unpadded base64url-encoded SHA-256 hash.
func isS256Challenge(challenge string) bool {
	hash, err := base64.RawURLEncoding.DecodeString(challenge)
	return err == nil && len(hash) == 32
}

// oauthError is an OAuth 2.0 error code and description.
type oauthError struct {
	code        string
	description string
}

// authorizationReply sends authorization responses and errors to a
// client's redirect URI, which must already be validated.
type authorizationReply struct {
	redirectURI string
	state       string
	// issuer is returned as the iss parameter (RFC 9207) so that clients of
	// several providers can tell which issuer responded.
	issuer string
	// fragment returns parameters in the URL fragment, which OIDC Core
	// §3.3.2.5 requires for responses that include an ID token.
	fragment bool
}

func (a authorizationReply) send(w http.ResponseWriter, r *http.Request, params url.Values) {
	params.Set("iss", a.issuer)
	if a.state != "" {
		params.Set("state", a.state)
	}

	target, err := url.Parse(a.redirectURI)
	if err != nil { // registered redirect URIs are validated at startup
		renderError(w, http.StatusInternalServerError, "The client's redirect URI is invalid.")
		return
	}
	location := ""
	if a.fragment {
		target.Fragment, target.RawFragment = "", ""
		location = target.String() + "#" + params.Encode()
	} else {
		query := target.Query()
		for name, values := range params {
			query[name] = values
		}
		target.RawQuery = query.Encode()
		location = target.String()
	}

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, location, http.StatusFound)
}

func (a authorizationReply) sendError(w http.ResponseWriter, r *http.Request, code, description string) {
	a.send(w, r, url.Values{"error": {code}, "error_description": {description}})
}
