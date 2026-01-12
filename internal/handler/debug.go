package handler

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates *template.Template

// titleCase capitalizes the first letter of a string.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func init() {
	funcMap := template.FuncMap{
		"title": titleCase,
	}
	templates = template.Must(template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"))
}

// DebugLoginData holds data for the debug login template.
type DebugLoginData struct {
	BaseURL        string
	CallbackURL    string
	Providers      []string
	CognitoEnabled bool
	CognitoAuthURL string
}

// DebugCallbackData holds data for the debug callback template.
type DebugCallbackData struct {
	Error            string
	ErrorDescription string
	Code             string
	State            string
	IDToken          string
	AccessToken      string
	DecodedClaims    string
	UserInfo         string
	UserInfoError    string
	TokenError       string
	QueryParams      map[string][]string
}

// DebugLogin handles GET /debug/login.
// This renders a simple login page for testing.
func (h *Handlers) DebugLogin(w http.ResponseWriter, r *http.Request) {
	baseURL := h.cfg.DebugBaseURL
	if baseURL == "" {
		baseURL = h.cfg.OIDCIssuer
	}

	data := DebugLoginData{
		BaseURL:        baseURL,
		CallbackURL:    baseURL + "/debug/callback",
		Providers:      h.providerRegistry.List(),
		CognitoEnabled: h.cfg.DebugCognitoEnabled && h.cfg.DebugCognitoDomain != "",
	}

	if data.CognitoEnabled {
		data.CognitoAuthURL = fmt.Sprintf("%s/oauth2/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile",
			h.cfg.DebugCognitoDomain,
			h.cfg.DebugCognitoClientID,
			url.QueryEscape(baseURL+"/debug/callback"),
		)
	}

	w.Header().Set("Content-Type", "text/html")
	if err := templates.ExecuteTemplate(w, "debug_login.html", data); err != nil {
		h.logger.Error("failed to render debug login template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// DebugCallback handles GET /debug/callback.
// This displays the tokens received from the authorization flow.
func (h *Handlers) DebugCallback(w http.ResponseWriter, r *http.Request) {
	baseURL := h.cfg.DebugBaseURL
	if baseURL == "" {
		baseURL = h.cfg.OIDCIssuer
	}

	data := DebugCallbackData{
		Error:            r.URL.Query().Get("error"),
		ErrorDescription: r.URL.Query().Get("error_description"),
		Code:             r.URL.Query().Get("code"),
		State:            r.URL.Query().Get("state"),
		IDToken:          r.URL.Query().Get("id_token"),
		QueryParams:      r.URL.Query(),
	}

	// If we have a code, exchange it for tokens
	if data.Code != "" && data.Error == "" {
		tokenResp, err := h.exchangeCodeForTokens(baseURL, data.Code)
		if err != nil {
			data.TokenError = err.Error()
		} else {
			if idToken, ok := tokenResp["id_token"].(string); ok {
				data.IDToken = idToken
			}
			if accessToken, ok := tokenResp["access_token"].(string); ok {
				data.AccessToken = accessToken

				// Fetch userinfo with the access token
				userInfo, err := h.fetchUserInfo(baseURL, accessToken)
				if err != nil {
					data.UserInfoError = err.Error()
				} else {
					data.UserInfo = userInfo
				}
			}
		}
	}

	if data.IDToken != "" {
		data.DecodedClaims = decodeJWTClaims(data.IDToken)
	}

	w.Header().Set("Content-Type", "text/html")
	if err := templates.ExecuteTemplate(w, "debug_callback.html", data); err != nil {
		h.logger.Error("failed to render debug callback template", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// exchangeCodeForTokens exchanges an authorization code for tokens.
func (h *Handlers) exchangeCodeForTokens(baseURL, code string) (map[string]interface{}, error) {
	tokenURL := baseURL + "/token"
	redirectURI := baseURL + "/debug/callback"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("client_id", "test-client")
	data.Set("client_secret", "test-secret")

	resp, err := http.PostForm(tokenURL, data)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing token response: %w", err)
	}

	if errMsg, ok := result["error"].(string); ok {
		errDesc, _ := result["error_description"].(string)
		return nil, fmt.Errorf("%s: %s", errMsg, errDesc)
	}

	return result, nil
}

// fetchUserInfo calls the userinfo endpoint with an access token.
func (h *Handlers) fetchUserInfo(baseURL, accessToken string) (string, error) {
	userInfoURL := baseURL + "/userinfo"

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return "", fmt.Errorf("creating userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading userinfo response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo returned status %d: %s", resp.StatusCode, string(body))
	}

	// Pretty print the JSON
	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return string(body), nil
	}

	pretty, err := json.MarshalIndent(userInfo, "", "  ")
	if err != nil {
		return string(body), nil
	}

	return string(pretty), nil
}

// decodeJWTClaims decodes the claims from a JWT without verification.
func decodeJWTClaims(tokenString string) string {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "Invalid JWT format"
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Sprintf("Failed to decode payload: %v", err)
	}

	// Pretty print JSON
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return string(payload)
	}

	pretty, err := json.MarshalIndent(claims, "", "  ")
	if err != nil {
		return string(payload)
	}

	return string(pretty)
}
