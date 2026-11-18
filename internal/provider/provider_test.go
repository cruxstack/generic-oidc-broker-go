package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cruxstack/generic-oidc-broker/internal/config"
	"github.com/cruxstack/generic-oidc-broker/internal/token"
)

// fakeUpstream serves a token endpoint and the given JSON responses by path.
func fakeUpstream(t *testing.T, responses map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"upstream-token","token_type":"bearer"}`))
	})
	for path, body := range responses {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer upstream-token" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if status, ok := body.(int); ok {
				http.Error(w, http.StatusText(status), status)
				return
			}
			_ = json.NewEncoder(w).Encode(body)
		})
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestProvider(t *testing.T, kind, userPath string, upstream *httptest.Server, prefix bool) *Provider {
	t.Helper()
	p, err := New(config.Provider{
		Name:          "my-" + kind,
		Type:          kind,
		ClientID:      "client",
		ClientSecret:  "secret",
		CallbackURL:   "https://broker.example.com/auth/my-" + kind + "/callback",
		AuthURL:       upstream.URL + "/authorize",
		TokenURL:      upstream.URL + "/token",
		UserURL:       upstream.URL + userPath,
		PrefixSubject: &prefix,
	}, upstream.Client())
	require.NoError(t, err)
	return p
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name      string
		kind      string
		userPath  string
		responses map[string]any
		want      token.Identity
	}{
		{
			name:     "twitter",
			kind:     "twitter",
			userPath: "/2/users/me",
			responses: map[string]any{"/2/users/me": map[string]any{"data": map[string]any{
				"id": "7", "name": "Ada", "username": "ada", "profile_image_url": "https://img/ada",
			}}},
			want: token.Identity{Subject: "my-twitter:7", Name: "Ada", PreferredUsername: "ada", Picture: "https://img/ada"},
		},
		{
			name:     "github with verified primary email",
			kind:     "github",
			userPath: "/user",
			responses: map[string]any{
				"/user": map[string]any{"id": 42, "login": "ada", "name": "Ada", "email": "public@example.com", "avatar_url": "https://img/ada"},
				"/user/emails": []map[string]any{
					{"email": "other@example.com", "primary": false, "verified": true},
					{"email": "ada@example.com", "primary": true, "verified": true},
				},
			},
			want: token.Identity{Subject: "my-github:42", Name: "Ada", PreferredUsername: "ada", Email: "ada@example.com", EmailVerified: true, Picture: "https://img/ada"},
		},
		{
			name:     "github with unverified primary email",
			kind:     "github",
			userPath: "/user",
			responses: map[string]any{
				"/user":        map[string]any{"id": 42, "login": "ada"},
				"/user/emails": []map[string]any{{"email": "ada@example.com", "primary": true, "verified": false}},
			},
			want: token.Identity{Subject: "my-github:42", PreferredUsername: "ada", Email: "ada@example.com"},
		},
		{
			name:     "github without the user:email scope",
			kind:     "github",
			userPath: "/user",
			responses: map[string]any{
				"/user":        map[string]any{"id": 42, "login": "ada", "email": "public@example.com"},
				"/user/emails": http.StatusNotFound,
			},
			// The public profile email is never reported as verified.
			want: token.Identity{Subject: "my-github:42", PreferredUsername: "ada", Email: "public@example.com"},
		},
		{
			name:     "google",
			kind:     "google",
			userPath: "/userinfo",
			responses: map[string]any{"/userinfo": map[string]any{
				"sub": "1234", "name": "Ada", "email": "ada@example.com", "email_verified": true, "picture": "https://img/ada",
			}},
			want: token.Identity{Subject: "my-google:1234", Name: "Ada", Email: "ada@example.com", EmailVerified: true, Picture: "https://img/ada"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newTestProvider(t, tt.kind, tt.userPath, fakeUpstream(t, tt.responses), true)
			got, err := p.Authenticate(context.Background(), "code", "verifier")
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthenticate_UnprefixedSubject(t *testing.T) {
	upstream := fakeUpstream(t, map[string]any{"/userinfo": map[string]any{"sub": "1234"}})
	p := newTestProvider(t, "google", "/userinfo", upstream, false)

	got, err := p.Authenticate(context.Background(), "code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "1234", got.Subject)
}

func TestAuthenticate_Errors(t *testing.T) {
	tests := map[string]struct {
		kind, userPath string
		responses      map[string]any
		wantErr        string
	}{
		"missing user ID":        {"google", "/userinfo", map[string]any{"/userinfo": map[string]any{"name": "Ada"}}, "without an ID"},
		"missing GitHub user ID": {"github", "/user", map[string]any{"/user": map[string]any{"login": "ada"}, "/user/emails": []any{}}, "without an ID"},
		"profile request fails":  {"twitter", "/me", map[string]any{"/me": http.StatusInternalServerError}, "HTTP status 500"},
		"emails request fails":   {"github", "/user", map[string]any{"/user": map[string]any{"id": 1}, "/user/emails": http.StatusInternalServerError}, "HTTP status 500"},
		"malformed profile":      {"google", "/userinfo", map[string]any{"/userinfo": "not an object"}, "decoding"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := newTestProvider(t, tt.kind, tt.userPath, fakeUpstream(t, tt.responses), true)
			_, err := p.Authenticate(context.Background(), "code", "verifier")
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestAuthenticate_TokenEndpointError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	t.Cleanup(upstream.Close)
	p := newTestProvider(t, "google", "/userinfo", upstream, true)

	_, err := p.Authenticate(context.Background(), "code", "verifier")
	assert.ErrorContains(t, err, "invalid_grant")
}

func TestAuthCodeURL(t *testing.T) {
	upstream := fakeUpstream(t, nil)
	tests := map[string]bool{"twitter": true, "github": false, "google": true}
	for kind, pkce := range tests {
		t.Run(kind, func(t *testing.T) {
			p := newTestProvider(t, kind, "/user", upstream, true)
			u, err := url.Parse(p.AuthCodeURL("the-state", "the-verifier"))
			require.NoError(t, err)

			q := u.Query()
			assert.Equal(t, upstream.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)
			assert.Equal(t, "the-state", q.Get("state"))
			assert.Equal(t, "client", q.Get("client_id"))
			assert.Equal(t, "https://broker.example.com/auth/my-"+kind+"/callback", q.Get("redirect_uri"))
			assert.Equal(t, pkce, q.Get("code_challenge") != "")
		})
	}
}

func TestNew_DefaultsAndOverrides(t *testing.T) {
	p, err := New(config.Provider{Name: "gh", Type: "github", ClientID: "id", ClientSecret: "s", CallbackURL: "https://b/cb"}, http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "https://api.github.com/user", p.userURL)
	assert.Equal(t, []string{"read:user", "user:email"}, p.oauth.Scopes)

	p, err = New(config.Provider{Name: "gh", Type: "github", Scopes: []string{"read:user"}, UserURL: "https://ghe/api/v3/user"}, http.DefaultClient)
	require.NoError(t, err)
	assert.Equal(t, "https://ghe/api/v3/user", p.userURL)
	assert.Equal(t, []string{"read:user"}, p.oauth.Scopes)
}

func TestNew_UnknownType(t *testing.T) {
	_, err := New(config.Provider{Name: "x", Type: "facebook"}, http.DefaultClient)
	assert.ErrorContains(t, err, `unknown type "facebook"`)
}

func TestRegistry(t *testing.T) {
	r, err := NewRegistry([]config.Provider{
		{Name: "zeta", Type: "google"},
		{Name: "alpha", Type: "github"},
	}, http.DefaultClient)
	require.NoError(t, err)

	assert.Equal(t, []string{"alpha", "zeta"}, r.Names())
	assert.Equal(t, "zeta", r.Get("zeta").Name())
	assert.Nil(t, r.Get("missing"))
}
