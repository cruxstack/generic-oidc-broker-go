package handler

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// errNoClientAuth means the request carried no client credentials.
var errNoClientAuth = errors.New("client authentication is required")

// clientCredentials are the credentials a client presented to the token
// endpoint.
type clientCredentials struct {
	id, secret string
	// basic is set for HTTP Basic authentication (client_secret_basic).
	basic bool
}

// readClientCredentials reads the client's credentials from HTTP Basic
// authentication or the form body (client_secret_post). r.ParseForm must
// have been called. RFC 6749 §2.3 forbids using both methods.
func readClientCredentials(r *http.Request) (clientCredentials, error) {
	formID, formSecret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	basicID, basicSecret, hasBasic := r.BasicAuth()

	switch {
	case hasBasic && formSecret != "":
		return clientCredentials{}, errors.New("use either HTTP Basic authentication or client_secret, not both")
	case hasBasic && formID != "" && !sameClientID(formID, basicID):
		return clientCredentials{}, errors.New("client_id does not match the Authorization header")
	case hasBasic:
		return clientCredentials{id: basicID, secret: basicSecret, basic: true}, nil
	case formID == "":
		return clientCredentials{}, errNoClientAuth
	default:
		return clientCredentials{id: formID, secret: formSecret}, nil
	}
}

// sameClientID compares a client_id form value with a Basic authentication
// user name, which may be form-urlencoded.
func sameClientID(formID, basicID string) bool {
	decoded, err := url.QueryUnescape(basicID)
	return formID == basicID || (err == nil && formID == decoded)
}

// authenticateClient returns the client identified by creds if its secret
// matches.
func (h *Handler) authenticateClient(creds clientCredentials) (config.Client, bool) {
	if client, ok := h.matchClient(creds.id, creds.secret); ok {
		return client, true
	}
	if !creds.basic {
		return config.Client{}, false
	}
	// RFC 6749 §2.3.1 has clients form-urlencode Basic credentials, but many
	// send them raw, so both forms are accepted.
	id, idErr := url.QueryUnescape(creds.id)
	secret, secretErr := url.QueryUnescape(creds.secret)
	if idErr != nil || secretErr != nil || (id == creds.id && secret == creds.secret) {
		return config.Client{}, false
	}
	return h.matchClient(id, secret)
}

func (h *Handler) matchClient(id, secret string) (config.Client, bool) {
	client, ok := h.cfg.Client(id)
	// Compare even for unknown clients so that timing doesn't reveal which
	// client IDs exist.
	match := subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(secret)) == 1
	return client, ok && secret != "" && match
}
