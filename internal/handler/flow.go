package handler

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

const (
	flowCookieName = "oidc_broker_flow"
	// flowTTL is how long a user has to finish signing in at the provider.
	flowTTL = 10 * time.Minute
	// maxPendingFlows bounds how many sign-ins one browser can have in
	// progress at once, for example in several tabs. The oldest is dropped
	// first. Fewer are kept when their requests are too large to fit in
	// maxFlowCookieValueLength together.
	maxPendingFlows = 3
	// maxFlowCookieValueLength keeps the cookie within browsers' limit of
	// 4096 bytes for a cookie's name and value.
	maxFlowCookieValueLength = 4096 - len(flowCookieName) - len("=")
)

// errFlowTooLarge means an authorization request does not fit in the flow
// cookie even on its own.
var errFlowTooLarge = errors.New("the authorization request is too large for the sign-in cookie")

// flowCookie keeps authorization requests in progress in an encrypted,
// authenticated cookie while the user signs in at the provider. Requests are
// keyed by the state parameter sent to the provider, so a callback can only
// complete a sign-in started in the same browser.
type flowCookie struct {
	codec  *securecookie.SecureCookie
	secure bool
	now    func() time.Time
}

// pendingFlows maps provider state values to authorization requests.
type pendingFlows map[string]authorizationRequest

func newFlowCookie(secret string, secure bool) (*flowCookie, error) {
	hashKey, err := hkdf.Key(sha256.New, []byte(secret), nil, "oidc-broker flow cookie authentication", 32)
	if err != nil {
		return nil, fmt.Errorf("deriving cookie authentication key: %w", err)
	}
	blockKey, err := hkdf.Key(sha256.New, []byte(secret), nil, "oidc-broker flow cookie encryption", 32)
	if err != nil {
		return nil, fmt.Errorf("deriving cookie encryption key: %w", err)
	}
	codec := securecookie.New(hashKey, blockKey).
		MaxAge(int(flowTTL.Seconds())).
		// save and load enforce maxFlowCookieValueLength instead, so that add
		// can make room by dropping older sign-ins.
		MaxLength(0).
		SetSerializer(securecookie.JSONEncoder{})
	return &flowCookie{codec: codec, secure: secure, now: time.Now}, nil
}

// add stores req under state. Older requests are dropped, oldest first, to
// stay within maxPendingFlows and the cookie size limit. It returns
// errFlowTooLarge if req does not fit in the cookie on its own.
func (f *flowCookie) add(w http.ResponseWriter, r *http.Request, state string, req authorizationRequest) error {
	flows := f.load(r)
	for len(flows) >= maxPendingFlows {
		delete(flows, flows.oldest())
	}
	for {
		flows[state] = req
		err := f.save(w, flows)
		if !errors.Is(err, errFlowTooLarge) {
			return err
		}
		delete(flows, state)
		if len(flows) == 0 {
			return errFlowTooLarge
		}
		delete(flows, flows.oldest())
	}
}

// take removes and returns the request stored under state.
func (f *flowCookie) take(w http.ResponseWriter, r *http.Request, state string) (authorizationRequest, bool, error) {
	flows := f.load(r)
	req, ok := flows[state]
	if !ok || state == "" {
		return authorizationRequest{}, false, nil
	}
	delete(flows, state)
	return req, true, f.save(w, flows)
}

// load returns the unexpired requests in the cookie. A missing, oversized,
// expired or tampered cookie yields none.
func (f *flowCookie) load(r *http.Request) pendingFlows {
	flows := pendingFlows{}
	cookie, err := r.Cookie(flowCookieName)
	if err != nil || len(cookie.Value) > maxFlowCookieValueLength ||
		f.codec.Decode(flowCookieName, cookie.Value, &flows) != nil {
		return pendingFlows{}
	}
	for state, req := range flows {
		if f.now().Sub(req.CreatedAt) > flowTTL {
			delete(flows, state)
		}
	}
	return flows
}

// save writes flows to the cookie, deleting it if there are none. If they do
// not fit, it returns errFlowTooLarge and writes nothing.
func (f *flowCookie) save(w http.ResponseWriter, flows pendingFlows) error {
	cookie := &http.Cookie{
		Name:     flowCookieName,
		Path:     "/",
		HttpOnly: true,
		Secure:   f.secure,
		// Lax lets the cookie accompany the provider's top-level redirect
		// back to the callback.
		SameSite: http.SameSiteLaxMode,
	}
	if len(flows) == 0 {
		cookie.MaxAge = -1
	} else {
		value, err := f.codec.Encode(flowCookieName, flows)
		if err != nil {
			return fmt.Errorf("encoding sign-in cookie: %w", err)
		}
		if len(value) > maxFlowCookieValueLength {
			return errFlowTooLarge
		}
		cookie.Value = value
		cookie.MaxAge = int(flowTTL.Seconds())
	}
	http.SetCookie(w, cookie)
	return nil
}

// oldest returns the state of the earliest request.
func (p pendingFlows) oldest() string {
	var oldest string
	for state, req := range p {
		if oldest == "" || req.CreatedAt.Before(p[oldest].CreatedAt) {
			oldest = state
		}
	}
	return oldest
}
