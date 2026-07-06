// Package httpserver runs an HTTP server with graceful shutdown.
package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Run starts the HTTP server and blocks until ctx is cancelled, then shuts down
// gracefully within a 10s timeout.
func Run(ctx context.Context, addr string, handler http.Handler, log *slog.Logger) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("http server listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Info("http server shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}
