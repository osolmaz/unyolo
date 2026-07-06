package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/osolmaz/hf-broker/internal/audit"
	"github.com/osolmaz/hf-broker/internal/config"
	"github.com/osolmaz/hf-broker/internal/httpapi"
	"github.com/osolmaz/hf-broker/internal/scope"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runWithContext(ctx, os.Getenv, os.Stdout, os.Stderr)
}

func runWithContext(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	scp, err := scope.LoadFile(cfg.ScopeFile)
	if err != nil {
		return err
	}
	handler, err := httpapi.New(httpapi.Options{
		Config:  cfg,
		Scope:   scp,
		Audit:   audit.New(stdout),
		Context: ctx,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return serveWithContext(ctx, server, stderr)
}

func serveWithContext(ctx context.Context, server *http.Server, stderr io.Writer) error {
	errs := make(chan error, 1)
	go func() {
		errs <- server.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "hf-broker stopped")
		return nil
	case err := <-errs:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
