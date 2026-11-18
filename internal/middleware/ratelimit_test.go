package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/stretchr/testify/assert"
)

func newTestLimiter(limit int) (*Limiter, *time.Time) {
	now := time.Now()
	l := NewLimiter(limit, time.Minute)
	l.now = func() time.Time { return now }
	return l, &now
}

func TestLimiter_Allow(t *testing.T) {
	l, now := newTestLimiter(2)

	ok, _ := l.Allow("a")
	assert.True(t, ok)
	ok, _ = l.Allow("a")
	assert.True(t, ok)

	*now = now.Add(20 * time.Second)
	ok, retryAfter := l.Allow("a")
	assert.False(t, ok)
	assert.Equal(t, 40*time.Second, retryAfter)

	ok, _ = l.Allow("b")
	assert.True(t, ok, "keys are limited independently")

	*now = now.Add(40 * time.Second)
	ok, _ = l.Allow("a")
	assert.True(t, ok, "the limit resets after the window")
}

func TestLimiter_BlockedAndRecord(t *testing.T) {
	l, _ := newTestLimiter(2)

	blocked, _ := l.Blocked("a")
	assert.False(t, blocked)
	l.Record("a")
	l.Record("a")
	blocked, retryAfter := l.Blocked("a")
	assert.True(t, blocked)
	assert.Equal(t, time.Minute, retryAfter)
}

func TestLimiter_SweepsEndedWindows(t *testing.T) {
	l, now := newTestLimiter(1)
	l.Allow("a")
	*now = now.Add(2 * time.Minute)
	l.Allow("b")
	assert.NotContains(t, l.windows, "a")
}

func TestClientKey(t *testing.T) {
	tests := map[string]string{
		"203.0.113.7:1234":              "203.0.113.7",
		"[::ffff:203.0.113.7]:1234":     "203.0.113.7",
		"[2001:db8:1:2:3:4:5:6]:1234":   "2001:db8:1:2::/64",
		"[2001:db8:1:2:ff:ff:ff:ff]:99": "2001:db8:1:2::/64",
		"garbage":                       "unknown",
	}
	for remoteAddr, want := range tests {
		var got string
		handler := chimw.ClientIPFromRemoteAddr(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = ClientKey(r)
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		handler.ServeHTTP(httptest.NewRecorder(), req)
		assert.Equal(t, want, got, remoteAddr)
	}
}

func TestRateLimitByIP(t *testing.T) {
	l, _ := newTestLimiter(1)
	handler := chimw.ClientIPFromRemoteAddr(RateLimitByIP(l)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

	send := func(remoteAddr, forwardedFor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = remoteAddr
		req.Header.Set("X-Forwarded-For", forwardedFor)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	assert.Equal(t, http.StatusOK, send("203.0.113.7:1", "10.0.0.1").Code)
	rec := send("203.0.113.7:2", "10.0.0.2")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "spoofed X-Forwarded-For must not evade the limit")
	assert.Equal(t, "60", rec.Header().Get("Retry-After"))
	assert.Equal(t, http.StatusOK, send("198.51.100.1:1", "").Code)
}
