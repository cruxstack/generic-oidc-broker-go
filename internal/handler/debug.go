package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// The debug pages walk through a sign-in as an OIDC client would, against
// the broker itself or, optionally, an Amazon Cognito user pool that uses
// the broker as an identity provider. They are for development only.

//go:embed templates/*.html
var templateFS embed.FS

var debugTemplates = map[string]*template.Template{
	"login":    template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/debug_login.html")),
	"callback": template.Must(template.ParseFS(templateFS, "templates/layout.html", "templates/debug_callback.html")),
}

// debugPageCSP allows the debug pages' inline styles and nothing else.
const debugPageCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src https: data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

type debugLink struct {
	Label string
	URL   string
}

type debugLoginPage struct {
	SignIns   []debugLink
	Discovery []debugLink
}

type debugCallbackPage struct {
	Error            string
	ErrorDescription string
	ExchangeError    string
	IDToken          string
	IDTokenClaims    string
	AccessToken      string
	Userinfo         string
	UserinfoError    string
}

// DebugLogin handles GET /debug/login, which links to a sign-in with each
// provider.
func (h *Handler) DebugLogin(w http.ResponseWriter, _ *http.Request) {
	base := h.cfg.Debug.BaseURL
	var page debugLoginPage
	for _, name := range h.providers.Names() {
		issuer := base + "/providers/" + name
		params := h.debugAuthorizationParams(h.cfg.Debug.ClientID, "provider:"+name)
		page.SignIns = append(page.SignIns, debugLink{Label: name, URL: issuer + "/authorize?" + params.Encode()})
		page.Discovery = append(page.Discovery, debugLink{Label: name, URL: issuer + "/.well-known/openid-configuration"})
	}
	if cognito := h.cfg.Debug.Cognito; cognito.Enabled {
		params := h.debugAuthorizationParams(cognito.ClientID, "cognito")
		page.SignIns = append(page.SignIns, debugLink{Label: "Amazon Cognito", URL: cognito.Domain + "/oauth2/authorize?" + params.Encode()})
	}
	h.renderDebugPage(w, "login", page)
}

// debugAuthorizationParams returns an authorization request for the debug
// callback. The state records which issuer the code must be redeemed at.
func (h *Handler) debugAuthorizationParams(clientID, target string) url.Values {
	return url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {h.cfg.Debug.BaseURL + "/debug/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {target + ":" + rand.Text()},
		"nonce":         {rand.Text()},
	}
}

// DebugCallback handles GET /debug/callback. It redeems the authorization
// code, calls the userinfo endpoint and shows the results.
func (h *Handler) DebugCallback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	page := debugCallbackPage{
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
	}
	if page.Error == "" {
		h.completeDebugSignIn(r.Context(), query.Get("state"), query.Get("code"), &page)
	}
	h.renderDebugPage(w, "callback", page)
}

// debugIssuer is where the debug pages redeem a code: one of the broker's
// providers, or Cognito.
type debugIssuer struct {
	tokenURL     string
	userinfoURL  string
	clientID     string
	clientSecret string
}

// debugIssuerFor returns the issuer recorded in a debug state value, which
// is "provider:{name}:{random}" or "cognito:{random}".
func (h *Handler) debugIssuerFor(state string) (debugIssuer, bool) {
	parts := strings.Split(state, ":")
	switch {
	case len(parts) == 3 && parts[0] == "provider" && h.providers.Get(parts[1]) != nil:
		issuer := h.cfg.Debug.BaseURL + "/providers/" + parts[1]
		return debugIssuer{
			tokenURL:     issuer + "/token",
			userinfoURL:  issuer + "/userinfo",
			clientID:     h.cfg.Debug.ClientID,
			clientSecret: h.cfg.Debug.ClientSecret,
		}, true
	case len(parts) == 2 && parts[0] == "cognito" && h.cfg.Debug.Cognito.Enabled:
		cognito := h.cfg.Debug.Cognito
		return debugIssuer{
			tokenURL:     cognito.Domain + "/oauth2/token",
			userinfoURL:  cognito.Domain + "/oauth2/userInfo",
			clientID:     cognito.ClientID,
			clientSecret: cognito.ClientSecret,
		}, true
	default:
		return debugIssuer{}, false
	}
}

func (h *Handler) completeDebugSignIn(ctx context.Context, state, code string, page *debugCallbackPage) {
	issuer, ok := h.debugIssuerFor(state)
	if !ok || code == "" {
		page.ExchangeError = "The callback has no code or an unrecognized state. Start again from the debug login page."
		return
	}

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {h.cfg.Debug.BaseURL + "/debug/callback"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, issuer.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		page.ExchangeError = err.Error()
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(issuer.clientID, issuer.clientSecret)

	var tokens struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if err := h.debugDo(req, &tokens); err != nil {
		page.ExchangeError = "Token request failed: " + err.Error()
		return
	}
	page.IDToken, page.AccessToken = tokens.IDToken, tokens.AccessToken
	page.IDTokenClaims = jwtClaimsJSON(tokens.IDToken)

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, issuer.userinfoURL, nil)
	if err != nil {
		page.UserinfoError = err.Error()
		return
	}
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	var userinfo json.RawMessage
	if err := h.debugDo(req, &userinfo); err != nil {
		page.UserinfoError = "Userinfo request failed: " + err.Error()
		return
	}
	page.Userinfo = indentJSON(userinfo)
}

// debugDo sends req and decodes a 200 JSON response into out.
func (h *Handler) debugDo(req *http.Request, out any) error {
	resp, err := h.debugClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return json.Unmarshal(body, out)
}

func (h *Handler) renderDebugPage(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := debugTemplates[name].ExecuteTemplate(&buf, "layout", data); err != nil {
		h.logger.Error("rendering debug page", "page", name, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", debugPageCSP)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = buf.WriteTo(w)
}

// jwtClaimsJSON returns a JWT's claims as indented JSON, without verifying
// the signature, or "" if the token is malformed.
func jwtClaimsJSON(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	return indentJSON(payload)
}

func indentJSON(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return string(raw)
	}
	return buf.String()
}
