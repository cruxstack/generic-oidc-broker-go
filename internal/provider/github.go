package provider

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

// githubKind is GitHub OAuth apps. Custom endpoints support GitHub
// Enterprise Server, whose user URL is https://HOST/api/v3/user.
// https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
var githubKind = kind{
	endpoint: oauth2.Endpoint{
		AuthURL:   "https://github.com/login/oauth/authorize",
		TokenURL:  "https://github.com/login/oauth/access_token",
		AuthStyle: oauth2.AuthStyleInParams,
	},
	userURL:   "https://api.github.com/user",
	scopes:    []string{"read:user", "user:email"},
	fetchUser: fetchGitHubUser,
}

var githubHeaders = http.Header{
	"Accept":               {"application/vnd.github+json"},
	"X-Github-Api-Version": {"2022-11-28"},
}

func fetchGitHubUser(ctx context.Context, client *http.Client, userURL string) (*user, error) {
	var profile struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := getJSON(ctx, client, userURL, githubHeaders, &profile); err != nil {
		return nil, err
	}

	u := &user{
		Name:     profile.Name,
		Username: profile.Login,
		Picture:  profile.AvatarURL,
		// The public profile email carries no verification status, so it is
		// only a fallback and never reported as verified.
		Email: profile.Email,
	}
	if profile.ID != 0 {
		u.ID = strconv.FormatInt(profile.ID, 10)
	}

	email, verified, err := githubPrimaryEmail(ctx, client, userURL+"/emails")
	if err != nil {
		return nil, err
	}
	if email != "" {
		u.Email, u.EmailVerified = email, verified
	}
	return u, nil
}

// githubPrimaryEmail returns the account's primary email address and whether
// GitHub has verified it. It returns no address when the token lacks the
// user:email scope.
func githubPrimaryEmail(ctx context.Context, client *http.Client, emailsURL string) (string, bool, error) {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	err := getJSON(ctx, client, emailsURL, githubHeaders, &emails)
	if statusErr, ok := errors.AsType[*statusError](err); ok &&
		(statusErr.status == http.StatusForbidden || statusErr.status == http.StatusNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}

	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}
	return "", false, nil
}
