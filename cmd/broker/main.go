// Command broker runs the OIDC broker HTTP server.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cruxstack/generic-oidc-broker/internal/app"
	"github.com/cruxstack/generic-oidc-broker/internal/config"
)

// shutdownTimeout is how long in-flight requests get to finish on shutdown.
const shutdownTimeout = 30 * time.Second

func main() {
	var level slog.LevelVar
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: &level}))
	if err := run(logger, &level); err != nil {
		logger.Error("broker stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, level *slog.LevelVar) error {
	cfg, err := config.Load(".")
	if err != nil {
		return fmt.Errorf("loading configuration: %w", err)
	}
	level.Set(cfg.LogLevel)
	for _, warning := range cfg.Warnings {
		logger.Warn(warning)
	}
	logger.Info("configuration loaded", "config", cfg)
	if cfg.Debug.Enabled {
		logger.Warn("debug pages are enabled at /debug/login; do not enable them in production")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	broker, err := app.New(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer broker.Close()

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           broker.Handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// Long enough for the callback's requests to the upstream provider.
		WriteTimeout: 45 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", srv.Addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutting down: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
