package testutil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// MockTwitterUser represents a mock Twitter user.
type MockTwitterUser struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Username        string `json:"username"`
	ProfileImageURL string `json:"profile_image_url"`
}

// MockTwitterServer is a mock Twitter OAuth 2.0 server for testing.
type MockTwitterServer struct {
	Server *httptest.Server

	mu           sync.RWMutex
	users        map[string]*MockTwitterUser // code -> user
	accessTokens map[string]*MockTwitterUser // token -> user
	nextUserID   int
}

// NewMockTwitterServer creates a new mock Twitter server.
func NewMockTwitterServer() *MockTwitterServer {
	m := &MockTwitterServer{
		users:        make(map[string]*MockTwitterUser),
		accessTokens: make(map[string]*MockTwitterUser),
		nextUserID:   1000,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/i/oauth2/authorize", m.handleAuthorize)
	mux.HandleFunc("/2/oauth2/token", m.handleToken)
	mux.HandleFunc("/2/users/me", m.handleUserInfo)

	m.Server = httptest.NewServer(mux)
	return m
}

// Close shuts down the mock server.
func (m *MockTwitterServer) Close() {
	m.Server.Close()
}

// URL returns the base URL of the mock server.
func (m *MockTwitterServer) URL() string {
	return m.Server.URL
}

// AuthURL returns the authorization endpoint URL.
func (m *MockTwitterServer) AuthURL() string {
	return m.Server.URL + "/i/oauth2/authorize"
}

// TokenURL returns the token endpoint URL.
func (m *MockTwitterServer) TokenURL() string {
	return m.Server.URL + "/2/oauth2/token"
}

// UserURL returns the user info endpoint URL.
func (m *MockTwitterServer) UserURL() string {
	return m.Server.URL + "/2/users/me"
}

// RegisterUser registers a mock user that will be returned when a code is exchanged.
// Returns the authorization code that should be used.
func (m *MockTwitterServer) RegisterUser(user *MockTwitterUser) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	code := generateMockCode()
	m.users[code] = user
	return code
}

// SetDefaultUser sets a default user that will be returned for any unregistered code.
func (m *MockTwitterServer) SetDefaultUser(user *MockTwitterUser) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Use a special key for default user
	m.users["__default__"] = user
}

// handleAuthorize handles the authorization endpoint.
// In a real flow, this would show a login page. For testing, we just redirect with a code.
func (m *MockTwitterServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}

	// Generate a code and register a default user
	m.mu.Lock()
	code := generateMockCode()
	if defaultUser, ok := m.users["__default__"]; ok {
		m.users[code] = defaultUser
	} else {
		m.users[code] = &MockTwitterUser{
			ID:              "mock-twitter-id",
			Name:            "Mock User",
			Username:        "mockuser",
			ProfileImageURL: "https://example.com/avatar.jpg",
		}
	}
	m.mu.Unlock()

	// Redirect back with code
	separator := "?"
	if strings.Contains(redirectURI, "?") {
		separator = "&"
	}
	redirectURL := redirectURI + separator + "code=" + code + "&state=" + state

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken handles the token endpoint.
func (m *MockTwitterServer) handleToken(w http.ResponseWriter, r *http.Request) {
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code is supported",
		})
		return
	}

	m.mu.Lock()
	user, ok := m.users[code]
	if !ok {
		// Check for default user
		user, ok = m.users["__default__"]
	}
	if !ok {
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}

	// Generate access token and store user mapping
	accessToken := generateMockToken()
	m.accessTokens[accessToken] = user
	delete(m.users, code) // Codes are single-use
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    7200,
		"refresh_token": "mock-refresh-token",
		"scope":         "tweet.read users.read offline.access",
	})
}

// handleUserInfo handles the user info endpoint.
func (m *MockTwitterServer) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")

	m.mu.RLock()
	user, ok := m.accessTokens[token]
	m.mu.RUnlock()

	if !ok {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": user,
	})
}

var mockCodeCounter int
var mockCodeMu sync.Mutex

func generateMockCode() string {
	mockCodeMu.Lock()
	defer mockCodeMu.Unlock()
	mockCodeCounter++
	return "mock-auth-code-" + string(rune('a'+mockCodeCounter%26)) + "-" + randomHex(8)
}

func generateMockToken() string {
	return "mock-access-token-" + randomHex(16)
}

func randomHex(n int) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, n)
	for i := range result {
		result[i] = hexChars[i%len(hexChars)]
	}
	return string(result)
}
