// Command mock-provider runs a fake Twitter/X, GitHub and Google OAuth 2.0
// server for the offline demo. See package mockprovider.
package main

import (
	"cmp"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/cruxstack/generic-oidc-broker/internal/mockprovider"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	addr := ":" + cmp.Or(os.Getenv("PORT"), "9999")

	srv := &http.Server{
		Addr:              addr,
		Handler:           mockprovider.New(logger, mockprovider.DefaultUsers).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	logger.Info("mock OAuth provider listening", "addr", addr, "providers", []string{"twitter", "github", "google"})
	if err := srv.ListenAndServe(); err != nil {
		logger.Error("mock provider stopped", "error", err)
		os.Exit(1)
	}
}
