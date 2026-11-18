// Package middleware provides the broker's HTTP middleware.
package middleware

import (
	"log/slog"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// RequestLogger logs one line per request. It must run after chi's
// RequestID and ClientIPFrom* middleware. Query strings are not logged
// because they carry authorization codes and tokens.
func RequestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				logger.LogAttrs(r.Context(), slog.LevelInfo, "request",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int64("duration_ms", time.Since(start).Milliseconds()),
					slog.Int("bytes", ww.BytesWritten()),
					slog.String("client_ip", chimw.GetClientIP(r.Context())),
					slog.String("request_id", chimw.GetReqID(r.Context())),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}
