package handler

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cruxstack/generic-oidc-broker/internal/store"
	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

// Callback handles GET /auth/{provider}/callback, where the provider returns
// the user after sign-in, and completes the client's authorization request.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	p := providerFrom(r)
	query := r.URL.Query()

	req, ok, err := h.flows.take(w, r, query.Get("state"))
	if err != nil {
		h.logger.Warn("clearing sign-in cookie", "error", err)
	}
	if !ok {
		renderError(w, http.StatusBadRequest, "This sign-in has expired or was started in another browser. Return to the application and try again.")
		return
	}
	if req.Provider != p.Name() {
		renderError(w, http.StatusBadRequest, "This sign-in was started with a different identity provider.")
		return
	}
	// The client may have been reconfigured since the sign-in started.
	if client, ok := h.cfg.Client(req.ClientID); !ok || !client.AllowsRedirectURI(req.RedirectURI) {
		renderError(w, http.StatusBadRequest, "The application is no longer allowed to use this redirect URI.")
		return
	}

	reply := authorizationReply{
		redirectURI: req.RedirectURI,
		state:       req.State,
		issuer:      h.cfg.ProviderIssuer(req.Provider),
		fragment:    req.ResponseType.IDToken,
	}

	if providerErr := query.Get("error"); providerErr != "" {
		h.logger.Info("sign-in did not complete at the provider", "provider", p.Name(), "error", providerErr)
		reply.sendError(w, r, clientErrorFor(providerErr), "sign-in with the identity provider did not complete")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()
	identity, err := p.Authenticate(ctx, query.Get("code"), req.ProviderVerifier)
	if err != nil {
		h.logger.Error("provider sign-in failed", "provider", p.Name(), "error", err)
		reply.sendError(w, r, "server_error", "could not sign in with the identity provider")
		return
	}

	params, err := h.authorizationResponse(r.Context(), req, identity)
	if err != nil {
		h.logger.Error("issuing authorization response", "provider", p.Name(), "error", err)
		reply.sendError(w, r, "server_error", "could not complete sign-in")
		return
	}
	reply.send(w, r, params)
}

// authorizationResponse issues the authorization code and/or ID token that
// req asked for.
func (h *Handler) authorizationResponse(ctx context.Context, req authorizationRequest, identity token.Identity) (url.Values, error) {
	issuer := h.cfg.ProviderIssuer(req.Provider)
	params := url.Values{}

	var code string
	if req.ResponseType.Code {
		code = rand.Text()
		err := h.codes.Save(ctx, code, store.AuthCode{
			ClientID:      req.ClientID,
			RedirectURI:   req.RedirectURI,
			Issuer:        issuer,
			Scope:         req.Scope,
			Nonce:         req.Nonce,
			CodeChallenge: req.CodeChallenge,
			Identity:      identity,
		})
		if err != nil {
			return nil, fmt.Errorf("saving authorization code: %w", err)
		}
		params.Set("code", code)
	}

	if req.ResponseType.IDToken {
		idToken, err := h.tokens.SignIDToken(token.IDToken{
			Issuer:   issuer,
			ClientID: req.ClientID,
			Identity: identity,
			Nonce:    req.Nonce,
			Code:     code,
		})
		if err != nil {
			return nil, err
		}
		params.Set("id_token", idToken)
	}
	return params, nil
}

// clientErrorFor maps a provider's authorization error to the error code
// returned to the client. Other provider errors are the broker's problem,
// not the client's, so they become server_error.
func clientErrorFor(providerErr string) string {
	switch providerErr {
	case "access_denied", "temporarily_unavailable":
		return providerErr
	default:
		return "server_error"
	}
}
