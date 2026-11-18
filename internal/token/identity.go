package token

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwt"
)

// Identity is the signed-in user as described by the broker's tokens.
type Identity struct {
	Subject           string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

// Claims returns the identity as standard OIDC claims. Empty values are
// omitted, except that email_verified accompanies any email.
func (id Identity) Claims() map[string]any {
	claims := map[string]any{"sub": id.Subject}
	for name, value := range map[string]string{
		"name":               id.Name,
		"preferred_username": id.PreferredUsername,
		"picture":            id.Picture,
	} {
		if value != "" {
			claims[name] = value
		}
	}
	if id.Email != "" {
		claims["email"] = id.Email
		claims["email_verified"] = id.EmailVerified
	}
	return claims
}

// identityFromToken reads the identity claims back out of a parsed token.
func identityFromToken(tok jwt.Token) (Identity, error) {
	var id Identity
	id.Subject, _ = tok.Subject()
	if id.Subject == "" {
		return Identity{}, fmt.Errorf("token has no subject")
	}
	for name, dst := range map[string]*string{
		"name":               &id.Name,
		"preferred_username": &id.PreferredUsername,
		"email":              &id.Email,
		"picture":            &id.Picture,
	} {
		if tok.Has(name) {
			value, err := jwt.Get[string](tok, name)
			if err != nil {
				return Identity{}, fmt.Errorf("claim %s: %w", name, err)
			}
			*dst = value
		}
	}
	if tok.Has("email_verified") {
		verified, err := jwt.Get[bool](tok, "email_verified")
		if err != nil {
			return Identity{}, fmt.Errorf("claim email_verified: %w", err)
		}
		id.EmailVerified = verified
	}
	return id, nil
}
