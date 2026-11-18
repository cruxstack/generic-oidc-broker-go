// Package mockprovider is a fake Twitter/X, GitHub and Google OAuth 2.0
// server for the offline demo and the end-to-end tests. Users sign in by
// choosing a test account on a login page.
//
// Each provider's endpoints live under its own path prefix, for example
// /github/authorize, /github/token, /github/user and /github/user/emails, and
// respond in that provider's format. The server checks what the real
// providers check: client authentication, redirect URIs and PKCE.
package mockprovider

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/oauth2"
)

// User is a test account.
type User struct {
	ID            string
	Name          string
	Username      string
	Email         string
	EmailVerified bool
	Picture       string
}

// DefaultUsers are the accounts offered on the login page.
var DefaultUsers = []User{
	{ID: "1001", Name: "Alice Demo", Username: "alice_demo", Email: "alice@example.com", EmailVerified: true, Picture: "https://example.com/avatars/alice.png"},
	{ID: "1002", Name: "Bob Tester", Username: "bob_test", Email: "bob@example.com", EmailVerified: true, Picture: "https://example.com/avatars/bob.png"},
	{ID: "1003", Name: "Charlie Dev", Username: "charlie_dev", Email: "charlie@example.com", EmailVerified: false, Picture: "https://example.com/avatars/charlie.png"},
}

// pkceProviders are the providers whose real counterparts require PKCE.
var pkceProviders = map[string]bool{"twitter": true, "google": true}

//go:embed login.html
var loginHTML string

var loginTemplate = template.Must(template.New("login").Parse(loginHTML))

// Server is the mock OAuth server. It is safe for concurrent use.
type Server struct {
	users  []User
	logger *slog.Logger

	mu     sync.Mutex
	logins map[string]authorization // awaiting a user choice, by login ID
	codes  map[string]grant         // authorization codes
	tokens map[string]User          // access tokens
}

// authorization is an authorization request awaiting sign-in.
type authorization struct {
	provider      string
	clientID      string
	redirectURI   string
	state         string
	codeChallenge string
}

// grant is an issued authorization code.
type grant struct {
	authorization
	user User
}

// New returns a server offering users on its login page.
func New(logger *slog.Logger, users []User) *Server {
	return &Server{
		users:  users,
		logger: logger,
		logins: map[string]authorization{},
		codes:  map[string]grant{},
		tokens: map[string]User{},
	}
}

// Handler returns the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	for _, provider := range []string{"twitter", "github", "google"} {
		mux.HandleFunc("GET /"+provider+"/authorize", s.authorize(provider))
		mux.HandleFunc("POST /"+provider+"/token", s.token(provider))
	}
	mux.HandleFunc("GET /twitter/user", s.userinfo(twitterProfile))
	mux.HandleFunc("GET /github/user", s.userinfo(githubProfile))
	mux.HandleFunc("GET /github/user/emails", s.userinfo(githubEmails))
	mux.HandleFunc("GET /google/userinfo", s.userinfo(googleProfile))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	return mux
}

// authorize starts sign-in and sends the user to the login page.
func (s *Server) authorize(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		req := authorization{
			provider:      provider,
			clientID:      q.Get("client_id"),
			redirectURI:   q.Get("redirect_uri"),
			state:         q.Get("state"),
			codeChallenge: q.Get("code_challenge"),
		}
		switch {
		case req.clientID == "" || req.redirectURI == "":
			http.Error(w, "client_id and redirect_uri are required", http.StatusBadRequest)
			return
		case provider != "github" && q.Get("response_type") != "code":
			http.Error(w, "response_type must be code", http.StatusBadRequest)
			return
		case pkceProviders[provider] && (req.codeChallenge == "" || q.Get("code_challenge_method") != "S256"):
			http.Error(w, "an S256 code_challenge is required", http.StatusBadRequest)
			return
		}

		loginID := rand.Text()
		s.mu.Lock()
		s.logins[loginID] = req
		s.mu.Unlock()

		s.logger.Info("authorization request", "provider", provider, "client_id", req.clientID)
		http.Redirect(w, r, "/login?"+url.Values{"login": {loginID}}.Encode(), http.StatusFound)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	loginID := r.URL.Query().Get("login")
	s.mu.Lock()
	req, ok := s.logins[loginID]
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown or expired login", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		LoginID  string
		Provider string
		Users    []User
	}{loginID, req.provider, s.users}
	if err := loginTemplate.Execute(w, data); err != nil {
		s.logger.Error("rendering login page", "error", err)
	}
}

// login signs in as the chosen user and returns to the client with a code.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	loginID, userID := r.PostFormValue("login"), r.PostFormValue("user_id")

	s.mu.Lock()
	req, ok := s.logins[loginID]
	delete(s.logins, loginID)
	s.mu.Unlock()
	if !ok {
		http.Error(w, "unknown or expired login", http.StatusBadRequest)
		return
	}
	user, ok := s.findUser(userID)
	if !ok {
		http.Error(w, "unknown user", http.StatusBadRequest)
		return
	}

	code := rand.Text()
	s.mu.Lock()
	s.codes[code] = grant{authorization: req, user: user}
	s.mu.Unlock()
	s.logger.Info("user signed in", "provider", req.provider, "user_id", user.ID)

	target, err := url.Parse(req.redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	query := target.Query()
	query.Set("code", code)
	if req.state != "" {
		query.Set("state", req.state)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// token redeems an authorization code for an access token.
func (s *Server) token(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_request", "malformed form")
			return
		}
		if r.PostForm.Get("grant_type") != "authorization_code" {
			tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
			return
		}

		clientID, clientSecret, ok := clientCredentials(provider, r)
		if !ok || clientID == "" || clientSecret == "" {
			tokenError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return
		}

		code := r.PostForm.Get("code")
		s.mu.Lock()
		g, ok := s.codes[code]
		delete(s.codes, code)
		s.mu.Unlock()

		switch {
		case !ok || g.provider != provider:
			tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown authorization code")
			return
		case g.clientID != clientID:
			tokenError(w, http.StatusBadRequest, "invalid_grant", "code was issued to another client")
			return
		case g.redirectURI != r.PostForm.Get("redirect_uri"):
			tokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
			return
		case g.codeChallenge != "" && !matchesChallenge(r.PostForm.Get("code_verifier"), g.codeChallenge):
			tokenError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}

		accessToken := rand.Text()
		s.mu.Lock()
		s.tokens[accessToken] = g.user
		s.mu.Unlock()

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": accessToken,
			"token_type":   "bearer",
			"expires_in":   7200,
		})
	}
}

// clientCredentials reads client credentials the way the provider expects:
// HTTP Basic for Twitter/X, form parameters for GitHub and Google.
func clientCredentials(provider string, r *http.Request) (id, secret string, ok bool) {
	if provider == "twitter" {
		return r.BasicAuth()
	}
	return r.PostForm.Get("client_id"), r.PostForm.Get("client_secret"), true
}

func matchesChallenge(verifier, challenge string) bool {
	computed := oauth2.S256ChallengeFromVerifier(verifier)
	return verifier != "" && subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

// userinfo serves a profile endpoint for the user an access token belongs to.
func (s *Server) userinfo(render func(User) any) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		accessToken, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		s.mu.Lock()
		user, ok := s.tokens[accessToken]
		s.mu.Unlock()
		if !ok {
			http.Error(w, "invalid access token", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, render(user))
	}
}

// twitterProfile is the X API v2 /2/users/me format.
func twitterProfile(u User) any {
	return map[string]any{"data": map[string]any{
		"id":                u.ID,
		"name":              u.Name,
		"username":          u.Username,
		"profile_image_url": u.Picture,
	}}
}

// githubProfile is the GitHub REST /user format. IDs are numbers and the
// public email is set only for verified accounts.
func githubProfile(u User) any {
	id, _ := strconv.ParseInt(u.ID, 10, 64)
	profile := map[string]any{"id": id, "login": u.Username, "name": u.Name, "avatar_url": u.Picture, "email": nil}
	if u.EmailVerified {
		profile["email"] = u.Email
	}
	return profile
}

// githubEmails is the GitHub REST /user/emails format.
func githubEmails(u User) any {
	return []map[string]any{{"email": u.Email, "primary": true, "verified": u.EmailVerified, "visibility": "public"}}
}

// googleProfile is the Google OpenID Connect userinfo format.
func googleProfile(u User) any {
	return map[string]any{"sub": u.ID, "name": u.Name, "email": u.Email, "email_verified": u.EmailVerified, "picture": u.Picture}
}

func (s *Server) findUser(id string) (User, bool) {
	for _, u := range s.users {
		if u.ID == id {
			return u, true
		}
	}
	return User{}, false
}

func tokenError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
