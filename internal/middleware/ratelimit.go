package middleware

import (
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// Limiter is a fixed-window rate limiter: each key may record up to limit
// events per window. It is safe for concurrent use.
type Limiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	windows   map[string]*fixedWindow
	nextSweep time.Time
	now       func() time.Time
}

type fixedWindow struct {
	start time.Time
	count int
}

// NewLimiter returns a limiter allowing limit events per key per window.
func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:   limit,
		window:  window,
		windows: map[string]*fixedWindow{},
		now:     time.Now,
	}
}

// Allow records an event for key and reports whether it is within the limit.
// When it is not, retryAfter is the time until the key's window resets.
func (l *Limiter) Allow(key string) (ok bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	w := l.current(key)
	if w.count >= l.limit {
		return false, l.untilReset(w)
	}
	w.count++
	return true, 0
}

// Blocked reports whether key has used up its limit, without recording an
// event. It pairs with Record to count only failures, such as failed logins.
func (l *Limiter) Blocked(key string) (blocked bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	w := l.current(key)
	if w.count >= l.limit {
		return true, l.untilReset(w)
	}
	return false, 0
}

// Record records an event for key.
func (l *Limiter) Record(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.current(key).count++
}

// current returns key's window, starting a new one if the last has ended.
// The caller must hold l.mu.
func (l *Limiter) current(key string) *fixedWindow {
	now := l.now()
	l.sweep(now)
	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= l.window {
		w = &fixedWindow{start: now}
		l.windows[key] = w
	}
	return w
}

func (l *Limiter) untilReset(w *fixedWindow) time.Duration {
	return w.start.Add(l.window).Sub(l.now())
}

// sweep drops ended windows at most once per window, bounding memory to the
// keys seen in roughly the last two windows. The caller must hold l.mu.
func (l *Limiter) sweep(now time.Time) {
	if now.Before(l.nextSweep) {
		return
	}
	for key, w := range l.windows {
		if now.Sub(w.start) >= l.window {
			delete(l.windows, key)
		}
	}
	l.nextSweep = now.Add(l.window)
}

// RateLimitByIP rejects requests from clients over the limiter's limit. The
// client IP comes from chi's ClientIPFrom* middleware, which must run first.
func RateLimitByIP(l *Limiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, retryAfter := l.Allow(ClientKey(r)); !ok {
				SetRetryAfter(w, retryAfter)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SetRetryAfter sets the Retry-After header in whole seconds, rounding up.
func SetRetryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
}

// ClientKey returns the rate-limiting key for the request's client: its IP
// address as set by chi's ClientIPFrom* middleware. IPv6 clients are grouped
// by /64 prefix, since one host usually controls a whole /64 and could
// otherwise rotate addresses to evade limits. Requests whose client IP is
// unknown share one key.
func ClientKey(r *http.Request) string {
	// Unmap so IPv4 clients of a dual-stack listener (::ffff:a.b.c.d) are
	// treated as IPv4.
	addr := chimw.GetClientIPAddr(r.Context()).Unmap()
	switch {
	case !addr.IsValid():
		return "unknown"
	case addr.Is6():
		prefix, _ := addr.Prefix(64)
		return prefix.String()
	default:
		return addr.String()
	}
}
