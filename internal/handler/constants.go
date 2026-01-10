package handler

import "time"

// Token expiration durations.
const (
	// IDTokenExpiry is the lifetime of an ID token.
	IDTokenExpiry = 1 * time.Hour

	// AccessTokenExpiry is the lifetime of an access token.
	AccessTokenExpiry = 1 * time.Hour

	// AccessTokenExpiresInSeconds is the expires_in value returned in token responses.
	AccessTokenExpiresInSeconds = 3600
)

// validResponseTypes defines the supported OIDC response types.
var validResponseTypes = map[string]bool{
	"code":           true,
	"id_token":       true,
	"token id_token": true,
	"id_token token": true,
	"code id_token":  true,
}
