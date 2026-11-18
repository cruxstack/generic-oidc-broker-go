package middleware

import "net/http"

// SecureHeaders sets response headers that are appropriate for every
// endpoint. no-referrer keeps authorization codes and tokens in URLs from
// leaking to other sites through the Referer header.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
