// Package main implements a standalone mock OAuth 2.0 provider server
// that can simulate Twitter, GitHub, and Google OAuth flows for offline testing.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// MockUser represents a test user for the mock OAuth providers.
type MockUser struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	Email           string `json:"email"`
	EmailVerified   bool   `json:"email_verified"`
	ProfileImageURL string `json:"profile_image_url"`
}

// Default test users available for login
var defaultUsers = []MockUser{
	{
		ID:              "1001",
		Name:            "Alice Demo",
		Username:        "alice_demo",
		Email:           "alice@example.com",
		EmailVerified:   true,
		ProfileImageURL: "https://api.dicebear.com/7.x/avataaars/svg?seed=alice",
	},
	{
		ID:              "1002",
		Name:            "Bob Tester",
		Username:        "bob_test",
		Email:           "bob@example.com",
		EmailVerified:   true,
		ProfileImageURL: "https://api.dicebear.com/7.x/avataaars/svg?seed=bob",
	},
	{
		ID:              "1003",
		Name:            "Charlie Dev",
		Username:        "charlie_dev",
		Email:           "charlie@example.com",
		EmailVerified:   false,
		ProfileImageURL: "https://api.dicebear.com/7.x/avataaars/svg?seed=charlie",
	},
}

// AuthSession stores pending OAuth authorization requests
type AuthSession struct {
	Provider     string
	RedirectURI  string
	State        string
	CodeVerifier string // For PKCE validation
	User         *MockUser
	CreatedAt    time.Time
}

// TokenSession stores issued access tokens
type TokenSession struct {
	Provider  string
	User      *MockUser
	CreatedAt time.Time
}

// MockOAuthServer handles mock OAuth flows for multiple providers
type MockOAuthServer struct {
	mu            sync.RWMutex
	authCodes     map[string]*AuthSession  // code -> session
	accessTokens  map[string]*TokenSession // token -> session
	pendingAuths  map[string]*AuthSession  // state -> session (for login flow)
	users         []MockUser
	logger        *slog.Logger
	loginTemplate *template.Template
}

// NewMockOAuthServer creates a new mock OAuth server
func NewMockOAuthServer(logger *slog.Logger) *MockOAuthServer {
	tmpl := template.Must(template.New("login").Parse(loginPageTemplate))

	return &MockOAuthServer{
		authCodes:     make(map[string]*AuthSession),
		accessTokens:  make(map[string]*TokenSession),
		pendingAuths:  make(map[string]*AuthSession),
		users:         defaultUsers,
		logger:        logger,
		loginTemplate: tmpl,
	}
}

// generateCode generates a random authorization code
func generateCode() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// generateToken generates a random access token
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Routes sets up all the mock OAuth routes
func (s *MockOAuthServer) Routes() http.Handler {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", s.handleHealth)

	// Twitter OAuth 2.0 endpoints
	mux.HandleFunc("/twitter/authorize", s.handleAuthorize("twitter"))
	mux.HandleFunc("/twitter/token", s.handleToken("twitter"))
	mux.HandleFunc("/twitter/user", s.handleTwitterUser)

	// GitHub OAuth endpoints
	mux.HandleFunc("/github/authorize", s.handleAuthorize("github"))
	mux.HandleFunc("/github/token", s.handleToken("github"))
	mux.HandleFunc("/github/user", s.handleGitHubUser)
	mux.HandleFunc("/github/user/emails", s.handleGitHubEmails)

	// Google OAuth 2.0 endpoints
	mux.HandleFunc("/google/authorize", s.handleAuthorize("google"))
	mux.HandleFunc("/google/token", s.handleToken("google"))
	mux.HandleFunc("/google/userinfo", s.handleGoogleUserInfo)

	// Login page (shared by all providers)
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/login/submit", s.handleLoginSubmit)

	return mux
}

func (s *MockOAuthServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// handleAuthorize handles the OAuth authorization endpoint for a provider
func (s *MockOAuthServer) handleAuthorize(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		codeChallenge := r.URL.Query().Get("code_challenge")

		if redirectURI == "" {
			http.Error(w, "missing redirect_uri", http.StatusBadRequest)
			return
		}

		s.logger.Info("authorization request",
			"provider", provider,
			"redirect_uri", redirectURI,
			"state", state,
		)

		// Store pending auth and redirect to login page
		s.mu.Lock()
		s.pendingAuths[state] = &AuthSession{
			Provider:     provider,
			RedirectURI:  redirectURI,
			State:        state,
			CodeVerifier: codeChallenge, // Store for PKCE (we'll verify later)
			CreatedAt:    time.Now(),
		}
		s.mu.Unlock()

		// Redirect to login page
		loginURL := fmt.Sprintf("/login?state=%s&provider=%s", url.QueryEscape(state), provider)
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}

// handleLogin renders the login page
func (s *MockOAuthServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	provider := r.URL.Query().Get("provider")

	s.mu.RLock()
	_, exists := s.pendingAuths[state]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "invalid or expired session", http.StatusBadRequest)
		return
	}

	data := struct {
		Provider string
		State    string
		Users    []MockUser
	}{
		Provider: provider,
		State:    state,
		Users:    s.users,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.loginTemplate.Execute(w, data); err != nil {
		s.logger.Error("template execution failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// handleLoginSubmit processes the login form submission
func (s *MockOAuthServer) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	state := r.FormValue("state")
	userID := r.FormValue("user_id")

	s.mu.Lock()
	session, exists := s.pendingAuths[state]
	if !exists {
		s.mu.Unlock()
		http.Error(w, "invalid or expired session", http.StatusBadRequest)
		return
	}

	// Find the selected user
	var selectedUser *MockUser
	for i := range s.users {
		if s.users[i].ID == userID {
			selectedUser = &s.users[i]
			break
		}
	}

	if selectedUser == nil {
		s.mu.Unlock()
		http.Error(w, "invalid user", http.StatusBadRequest)
		return
	}

	// Generate auth code
	code := generateCode()
	session.User = selectedUser
	s.authCodes[code] = session
	delete(s.pendingAuths, state)
	s.mu.Unlock()

	s.logger.Info("user authenticated",
		"provider", session.Provider,
		"user_id", selectedUser.ID,
		"username", selectedUser.Username,
	)

	// Redirect back to the OIDC broker with the code
	redirectURL := session.RedirectURI
	separator := "?"
	if strings.Contains(redirectURL, "?") {
		separator = "&"
	}
	redirectURL = fmt.Sprintf("%s%scode=%s&state=%s", redirectURL, separator, code, session.State)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken handles the OAuth token exchange endpoint
func (s *MockOAuthServer) handleToken(provider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}

		code := r.FormValue("code")
		grantType := r.FormValue("grant_type")

		if grantType != "authorization_code" {
			s.errorResponse(w, "unsupported_grant_type", "Only authorization_code is supported")
			return
		}

		s.mu.Lock()
		session, exists := s.authCodes[code]
		if !exists {
			s.mu.Unlock()
			s.errorResponse(w, "invalid_grant", "Invalid authorization code")
			return
		}

		if session.Provider != provider {
			s.mu.Unlock()
			s.errorResponse(w, "invalid_grant", "Code not valid for this provider")
			return
		}

		// Generate access token
		accessToken := generateToken()
		s.accessTokens[accessToken] = &TokenSession{
			Provider:  provider,
			User:      session.User,
			CreatedAt: time.Now(),
		}
		delete(s.authCodes, code) // Codes are single-use
		s.mu.Unlock()

		s.logger.Info("token issued",
			"provider", provider,
			"user_id", session.User.ID,
		)

		// Response format varies by provider
		response := map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   7200,
		}

		// GitHub uses a different format
		if provider == "github" {
			response["scope"] = "read:user,user:email"
		} else {
			response["refresh_token"] = "mock-refresh-token-" + generateCode()[:8]
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

// handleTwitterUser handles Twitter's user info endpoint
func (s *MockOAuthServer) handleTwitterUser(w http.ResponseWriter, r *http.Request) {
	user := s.getUserFromToken(w, r)
	if user == nil {
		return
	}

	// Twitter API v2 format
	response := map[string]interface{}{
		"data": map[string]interface{}{
			"id":                user.ID,
			"name":              user.Name,
			"username":          user.Username,
			"profile_image_url": user.ProfileImageURL,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGitHubUser handles GitHub's user info endpoint
func (s *MockOAuthServer) handleGitHubUser(w http.ResponseWriter, r *http.Request) {
	user := s.getUserFromToken(w, r)
	if user == nil {
		return
	}

	// GitHub API format
	response := map[string]interface{}{
		"id":         user.ID,
		"login":      user.Username,
		"name":       user.Name,
		"avatar_url": user.ProfileImageURL,
		"email":      user.Email,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGitHubEmails handles GitHub's user emails endpoint
func (s *MockOAuthServer) handleGitHubEmails(w http.ResponseWriter, r *http.Request) {
	user := s.getUserFromToken(w, r)
	if user == nil {
		return
	}

	// GitHub emails API format
	response := []map[string]interface{}{
		{
			"email":      user.Email,
			"primary":    true,
			"verified":   user.EmailVerified,
			"visibility": "public",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleGoogleUserInfo handles Google's userinfo endpoint
func (s *MockOAuthServer) handleGoogleUserInfo(w http.ResponseWriter, r *http.Request) {
	user := s.getUserFromToken(w, r)
	if user == nil {
		return
	}

	// Google userinfo format
	response := map[string]interface{}{
		"sub":            user.ID,
		"name":           user.Name,
		"email":          user.Email,
		"email_verified": user.EmailVerified,
		"picture":        user.ProfileImageURL,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// getUserFromToken extracts and validates the access token
func (s *MockOAuthServer) getUserFromToken(w http.ResponseWriter, r *http.Request) *MockUser {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return nil
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	s.mu.RLock()
	session, exists := s.accessTokens[token]
	s.mu.RUnlock()

	if !exists {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return nil
	}

	return session.User
}

// errorResponse sends an OAuth error response
func (s *MockOAuthServer) errorResponse(w http.ResponseWriter, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

// Login page HTML template
const loginPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mock {{.Provider}} Login</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        :root {
            --background: 0 0% 100%;
            --foreground: 240 10% 3.9%;
            --card: 0 0% 100%;
            --card-foreground: 240 10% 3.9%;
            --primary: 240 5.9% 10%;
            --primary-foreground: 0 0% 98%;
            --secondary: 240 4.8% 95.9%;
            --secondary-foreground: 240 5.9% 10%;
            --muted: 240 4.8% 95.9%;
            --muted-foreground: 240 3.8% 46.1%;
            --accent: 240 4.8% 95.9%;
            --accent-foreground: 240 5.9% 10%;
            --destructive: 0 84.2% 60.2%;
            --border: 240 5.9% 90%;
            --input: 240 5.9% 90%;
            --ring: 240 5.9% 10%;
            --radius: 0.5rem;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: hsl(240 10% 3.9%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            line-height: 1.5;
        }
        .container {
            background: hsl(var(--card));
            border-radius: var(--radius);
            border: 1px solid hsl(var(--border));
            box-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);
            padding: 32px;
            max-width: 420px;
            width: 100%;
        }
        .header {
            text-align: center;
            margin-bottom: 24px;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 2px 10px;
            font-size: 11px;
            font-weight: 500;
            border-radius: 9999px;
            background: hsl(var(--destructive));
            color: hsl(0 0% 98%);
            text-transform: uppercase;
            letter-spacing: 0.025em;
            margin-bottom: 12px;
        }
        h1 {
            color: hsl(var(--foreground));
            font-size: 20px;
            font-weight: 600;
            letter-spacing: -0.025em;
            margin-bottom: 4px;
        }
        .provider-name {
            text-transform: capitalize;
        }
        .subtitle {
            color: hsl(var(--muted-foreground));
            font-size: 14px;
        }
        .users-list {
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .user-card {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px;
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            cursor: pointer;
            transition: all 0.15s ease;
            background: hsl(var(--card));
        }
        .user-card:hover {
            border-color: hsl(var(--ring));
            background: hsl(var(--accent));
        }
        .user-card input[type="radio"] {
            display: none;
        }
        .user-card:has(input:checked) {
            border-color: hsl(var(--ring));
            background: hsl(var(--accent));
            box-shadow: 0 0 0 1px hsl(var(--ring));
        }
        .avatar {
            width: 44px;
            height: 44px;
            border-radius: 50%;
            background: hsl(var(--muted));
            border: 1px solid hsl(var(--border));
        }
        .user-info {
            flex: 1;
            min-width: 0;
        }
        .user-name {
            font-weight: 500;
            font-size: 14px;
            color: hsl(var(--foreground));
            margin-bottom: 1px;
        }
        .user-username {
            color: hsl(var(--muted-foreground));
            font-size: 13px;
        }
        .user-email {
            color: hsl(var(--muted-foreground));
            font-size: 12px;
            margin-top: 1px;
        }
        .checkmark {
            width: 20px;
            height: 20px;
            border: 1px solid hsl(var(--border));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.15s ease;
            flex-shrink: 0;
        }
        .user-card:has(input:checked) .checkmark {
            border-color: hsl(var(--primary));
            background: hsl(var(--primary));
        }
        .checkmark::after {
            content: '';
            width: 6px;
            height: 6px;
            background: hsl(var(--primary-foreground));
            border-radius: 50%;
            opacity: 0;
            transition: opacity 0.15s ease;
        }
        .user-card:has(input:checked) .checkmark::after {
            opacity: 1;
        }
        button {
            width: 100%;
            padding: 10px 16px;
            background: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
            border: none;
            border-radius: var(--radius);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            margin-top: 20px;
            transition: opacity 0.2s ease;
        }
        button:hover {
            opacity: 0.9;
        }
        button:active {
            opacity: 0.8;
        }
        .footer {
            text-align: center;
            margin-top: 16px;
            padding-top: 16px;
            border-top: 1px solid hsl(var(--border));
            color: hsl(var(--muted-foreground));
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <span class="badge">Demo Mode</span>
            <h1>Sign in with <span class="provider-name">{{.Provider}}</span></h1>
            <p class="subtitle">Select a test user to continue</p>
        </div>
        
        <form action="/login/submit" method="POST">
            <input type="hidden" name="state" value="{{.State}}">
            
            <div class="users-list">
                {{range $i, $user := .Users}}
                <label class="user-card">
                    <img class="avatar" src="{{$user.ProfileImageURL}}" alt="{{$user.Name}}">
                    <input type="radio" name="user_id" value="{{$user.ID}}" {{if eq $i 0}}checked{{end}}>
                    <div class="user-info">
                        <div class="user-name">{{$user.Name}}</div>
                        <div class="user-username">@{{$user.Username}}</div>
                        <div class="user-email">{{$user.Email}}</div>
                    </div>
                    <div class="checkmark"></div>
                </label>
                {{end}}
            </div>
            
            <button type="submit">Continue as Selected User</button>
        </form>
        
        <div class="footer">
            This is a mock OAuth provider for testing purposes only.
        </div>
    </div>
</body>
</html>`

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	server := NewMockOAuthServer(logger)

	logger.Info("starting mock OAuth provider",
		"port", port,
		"providers", []string{"twitter", "github", "google"},
	)

	fmt.Printf("\n")
	fmt.Printf("=================================================\n")
	fmt.Printf("  Mock OAuth Provider Server\n")
	fmt.Printf("=================================================\n")
	fmt.Printf("  Port: %s\n", port)
	fmt.Printf("\n")
	fmt.Printf("  Endpoints:\n")
	fmt.Printf("    Twitter:  /twitter/authorize, /twitter/token, /twitter/user\n")
	fmt.Printf("    GitHub:   /github/authorize, /github/token, /github/user\n")
	fmt.Printf("    Google:   /google/authorize, /google/token, /google/userinfo\n")
	fmt.Printf("\n")
	fmt.Printf("  Test Users:\n")
	for _, u := range defaultUsers {
		fmt.Printf("    - %s (@%s) - %s\n", u.Name, u.Username, u.Email)
	}
	fmt.Printf("=================================================\n\n")

	addr := fmt.Sprintf(":%s", port)
	if err := http.ListenAndServe(addr, server.Routes()); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
