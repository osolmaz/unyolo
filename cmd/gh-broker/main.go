package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/osolmaz/gh-broker/internal/config"
	"github.com/osolmaz/gh-broker/internal/httpapi"
	"github.com/osolmaz/gh-broker/internal/policy"
)

var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runWithArgs(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Fatalf("gh-broker: %v", err)
	}
}

func run(ctx context.Context) error {
	return runServer(ctx)
}

func runWithArgs(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return runServer(ctx)
	}
	switch args[0] {
	case "--version", "version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "setup":
		return runSetup(stdout, stderr, args[1:])
	default:
		return fmt.Errorf("usage: gh-broker [--version|version|setup]")
	}
}

func runServer(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	server, err := buildServer(cfg)
	if err != nil {
		return err
	}
	return serve(ctx, server, cfg.BindAddr, cfg.Port)
}

func buildServer(cfg config.Config) (*http.Server, error) {
	brokerPolicy, err := policy.LoadFile(cfg.ScopeFile)
	if err != nil {
		return nil, err
	}
	api, err := httpapi.New(cfg, brokerPolicy)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              cfg.BindAddr + ":" + cfg.Port,
		Handler:           api.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}, nil
}

func serve(ctx context.Context, server *http.Server, bindAddr string, port string) error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("gh-broker listening on %s:%s", bindAddr, port)
		errCh <- server.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return shutdown(server)
	}
}

func shutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shutdown server: %w", err)
	}
	return nil
}
