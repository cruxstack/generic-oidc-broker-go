// Package provider signs users in with upstream OAuth 2.0 identity
// providers (Twitter/X, GitHub and Google), whose sign-in the broker exposes
// as OpenID Connect.
package provider

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"golang.org/x/oauth2"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

// user is a profile as returned by an upstream provider.
type user struct {
	ID            string
	Name          string
	Username      string
	Email         string
	EmailVerified bool
	Picture       string
}

// fetchUserFunc reads the signed-in user's profile. client adds the user's
// access token to every request.
type fetchUserFunc func(ctx context.Context, client *http.Client, userURL string) (*user, error)

// kind describes a provider type: its default endpoints and scopes, and how
// to read its user profile.
type kind struct {
	endpoint  oauth2.Endpoint
	userURL   string
	scopes    []string
	pkce      bool
	fetchUser fetchUserFunc
}

var kinds = map[string]kind{
	"twitter": twitterKind,
	"github":  githubKind,
	"google":  googleKind,
}

// Provider signs users in with one configured upstream OAuth 2.0 app.
type Provider struct {
	name          string
	prefixSubject bool
	oauth         oauth2.Config
	pkce          bool
	userURL       string
	fetchUser     fetchUserFunc
	httpClient    *http.Client
}

// New creates a provider from its configuration. httpClient is used for all
// requests to the provider.
func New(cfg config.Provider, httpClient *http.Client) (*Provider, error) {
	k, ok := kinds[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("provider %q: unknown type %q (supported: twitter, github, google)", cfg.Name, cfg.Type)
	}

	endpoint := k.endpoint
	endpoint.AuthURL = cmp.Or(cfg.AuthURL, endpoint.AuthURL)
	endpoint.TokenURL = cmp.Or(cfg.TokenURL, endpoint.TokenURL)
	scopes := k.scopes
	if len(cfg.Scopes) > 0 {
		scopes = cfg.Scopes
	}

	return &Provider{
		name:          cfg.Name,
		prefixSubject: cfg.SubjectPrefixed(),
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  cfg.CallbackURL,
			Scopes:       slices.Clone(scopes),
		},
		pkce:       k.pkce,
		userURL:    cmp.Or(cfg.UserURL, k.userURL),
		fetchUser:  k.fetchUser,
		httpClient: httpClient,
	}, nil
}

// Name returns the provider's configured name.
func (p *Provider) Name() string {
	return p.name
}

// AuthCodeURL returns the provider URL that starts sign-in. verifier is the
// PKCE code verifier; it is ignored by providers without PKCE support.
func (p *Provider) AuthCodeURL(state, verifier string) string {
	if !p.pkce {
		return p.oauth.AuthCodeURL(state)
	}
	return p.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

// Authenticate redeems the authorization code from the provider's callback
// and returns the signed-in user's identity.
func (p *Provider) Authenticate(ctx context.Context, code, verifier string) (token.Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)

	var opts []oauth2.AuthCodeOption
	if p.pkce {
		opts = append(opts, oauth2.VerifierOption(verifier))
	}
	tok, err := p.oauth.Exchange(ctx, code, opts...)
	if err != nil {
		return token.Identity{}, fmt.Errorf("exchanging authorization code: %w", err)
	}

	u, err := p.fetchUser(ctx, p.oauth.Client(ctx, tok), p.userURL)
	if err != nil {
		return token.Identity{}, fmt.Errorf("fetching user profile: %w", err)
	}
	if u.ID == "" {
		return token.Identity{}, errors.New("provider returned a user profile without an ID")
	}

	return token.Identity{
		Subject:           p.subject(u.ID),
		Name:              u.Name,
		PreferredUsername: u.Username,
		Email:             u.Email,
		EmailVerified:     u.EmailVerified,
		Picture:           u.Picture,
	}, nil
}

// subject returns the sub claim for a provider user ID: "name:id", or just
// the ID when prefixing is disabled.
func (p *Provider) subject(userID string) string {
	if p.prefixSubject {
		return p.name + ":" + userID
	}
	return userID
}
