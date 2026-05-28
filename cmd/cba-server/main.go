package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/dutifuldev/gitcba/internal/config"
	"github.com/dutifuldev/gitcba/internal/githubaccess"
	"github.com/dutifuldev/gitcba/internal/httpapi"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		log.Fatalf("cba-server: %v", err)
	}
}

func run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	server, err := buildServer(cfg)
	if err != nil {
		return err
	}
	return serve(ctx, server, cfg.Port)
}

func buildServer(cfg config.Config) (*http.Server, error) {
	access, err := githubaccess.LoadFile(cfg.GitHubAccessFile)
	if err != nil {
		return nil, err
	}
	api, err := httpapi.New(cfg, access)
	if err != nil {
		return nil, err
	}
	return &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           api.Handler(),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}, nil
}

func serve(ctx context.Context, server *http.Server, port string) error {
	errCh := make(chan error, 1)
	go func() {
		log.Printf("cba-server listening on :%s", port)
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
