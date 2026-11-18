// Package store keeps authorization codes between the authorization response
// and the client's token request.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

// AuthCodeTTL is how long an authorization code can be redeemed. RFC 6749
// §4.1.2 recommends at most 10 minutes.
const AuthCodeTTL = 10 * time.Minute

// ErrNotFound is returned when a code is unknown, expired or already used.
var ErrNotFound = errors.New("authorization code not found")

// AuthCode is what the token endpoint needs to redeem an authorization code.
type AuthCode struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	Issuer      string `json:"issuer"`
	Scope       string `json:"scope"`
	Nonce       string `json:"nonce,omitempty"`
	// CodeChallenge is the client's PKCE S256 challenge, if it sent one.
	CodeChallenge string         `json:"code_challenge,omitempty"`
	Identity      token.Identity `json:"identity"`
}

// AuthCodes stores authorization codes. Codes are single use.
type AuthCodes interface {
	// Save stores data under code for AuthCodeTTL.
	Save(ctx context.Context, code string, data AuthCode) error
	// Consume removes the code and returns its data, or ErrNotFound.
	Consume(ctx context.Context, code string) (AuthCode, error)
	// Close releases the store's resources.
	Close() error
}
