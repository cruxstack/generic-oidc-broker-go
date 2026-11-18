package provider

import (
	"context"
	"net/http"

	"golang.org/x/oauth2"
)

// googleKind is Google sign-in. Profiles come from Google's OpenID Connect
// userinfo endpoint.
// https://developers.google.com/identity/openid-connect/openid-connect
var googleKind = kind{
	endpoint: oauth2.Endpoint{
		AuthURL:   "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:  "https://oauth2.googleapis.com/token",
		AuthStyle: oauth2.AuthStyleInParams,
	},
	userURL:   "https://openidconnect.googleapis.com/v1/userinfo",
	scopes:    []string{"openid", "profile", "email"},
	pkce:      true,
	fetchUser: fetchGoogleUser,
}

func fetchGoogleUser(ctx context.Context, client *http.Client, userURL string) (*user, error) {
	var info struct {
		Sub           string `json:"sub"`
		Name          string `json:"name"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Picture       string `json:"picture"`
	}
	if err := getJSON(ctx, client, userURL, nil, &info); err != nil {
		return nil, err
	}
	return &user{
		ID:            info.Sub,
		Name:          info.Name,
		Email:         info.Email,
		EmailVerified: info.EmailVerified,
		Picture:       info.Picture,
	}, nil
}
