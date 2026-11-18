package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
)

// twitterKind is Twitter/X OAuth 2.0. X does not share email addresses.
// https://docs.x.com/resources/fundamentals/authentication/oauth-2-0/authorization-code
var twitterKind = kind{
	endpoint: oauth2.Endpoint{
		AuthURL:   "https://x.com/i/oauth2/authorize",
		TokenURL:  "https://api.x.com/2/oauth2/token",
		AuthStyle: oauth2.AuthStyleInHeader,
	},
	userURL:   "https://api.x.com/2/users/me",
	scopes:    []string{"tweet.read", "users.read"},
	pkce:      true,
	fetchUser: fetchTwitterUser,
}

func fetchTwitterUser(ctx context.Context, client *http.Client, userURL string) (*user, error) {
	u, err := url.Parse(userURL)
	if err != nil {
		return nil, fmt.Errorf("parsing user URL: %w", err)
	}
	query := u.Query()
	query.Set("user.fields", "profile_image_url")
	u.RawQuery = query.Encode()

	var resp struct {
		Data struct {
			ID              string `json:"id"`
			Name            string `json:"name"`
			Username        string `json:"username"`
			ProfileImageURL string `json:"profile_image_url"`
		} `json:"data"`
	}
	if err := getJSON(ctx, client, u.String(), nil, &resp); err != nil {
		return nil, err
	}
	return &user{
		ID:       resp.Data.ID,
		Name:     resp.Data.Name,
		Username: resp.Data.Username,
		Picture:  resp.Data.ProfileImageURL,
	}, nil
}
