package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubsurface"
	"github.com/osolmaz/brokerkit/brokers/github/internal/httpapi"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
)

var version = "dev"

func main() {
	os.Exit(mainCode())
}

func mainCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return exitCodeForRun(runWithArgs(ctx, os.Args[1:], os.Stdout, os.Stderr), os.Stderr)
}

func run(ctx context.Context) error {
	return runServer(ctx)
}

//nolint:cyclop // Top-level CLI dispatch keeps every supported command explicit.
func runWithArgs(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return runServer(ctx)
	}
	switch args[0] {
	case "--version", "version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "setup":
		return runSetupWithContext(ctx, stdout, stderr, args[1:])
	case "doctor":
		return runDoctor(ctx, stdout, stderr, args[1:])
	case "operations":
		return runOperations(stdout, args[1:])
	case "operation":
		return runOperation(ctx, stdout, args[1:])
	case "stream":
		return runStream(ctx, stdout, args[1:])
	case "mcp":
		return runMCP(ctx, os.Getenv, os.Stdin, stdout, args[1:])
	default:
		if found, err := runGeneratedCLI(ctx, stdout, args); found {
			return err
		}
		return fmt.Errorf("usage: gh-broker [--version|version|doctor|setup|operations|operation|stream|mcp]")
	}
}

type exitError struct {
	code    int
	message string
}

func (err exitError) Error() string {
	return err.message
}

func exitCodeForRun(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var status exitError
	if errors.As(err, &status) {
		if status.message != "" {
			_, _ = fmt.Fprintln(stderr, "gh-broker:", status.message)
		}
		return status.code
	}
	_, _ = fmt.Fprintln(stderr, "gh-broker:", err)
	return 1
}

func runServer(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	servers, err := buildServers(ctx, cfg)
	if err != nil {
		return err
	}
	return serveServers(ctx, servers)
}

func buildServers(ctx context.Context, cfg config.Config) ([]*http.Server, error) {
	if err := githubsurface.Validate(); err != nil {
		return nil, fmt.Errorf("validate generated GitHub surface: %w", err)
	}
	brokerPolicy, err := policy.LoadFile(cfg.ScopeFile)
	if err != nil {
		return nil, err
	}
	api, err := httpapi.New(cfg, brokerPolicy)
	if err != nil {
		return nil, err
	}
	api.Start(ctx)
	servers := []*http.Server{configuredAgentServer(cfg.BindAddr, cfg.Port, api.Handler(), cfg)}
	if cfg.OperatorSecret != "" {
		servers = append(servers, configuredOperatorServer(cfg.OperatorBindAddr, cfg.OperatorPort, api.OperatorHandler(), cfg))
	}
	for _, server := range servers {
		server.RegisterOnShutdown(func() { _ = api.Close() })
	}
	return servers, nil
}

func configuredOperatorServer(bindAddr string, port string, handler http.Handler, cfg config.Config) *http.Server {
	server := configuredHTTPServer(bindAddr, port, handler, cfg)
	server.WriteTimeout = 0
	return server
}

func buildServer(ctx context.Context, cfg config.Config) (*http.Server, error) {
	servers, err := buildServers(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return servers[0], nil
}

func configuredHTTPServer(bindAddr string, port string, handler http.Handler, cfg config.Config) *http.Server {
	return &http.Server{
		Addr:              net.JoinHostPort(bindAddr, port),
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}
}

func configuredAgentServer(bindAddr string, port string, handler http.Handler, cfg config.Config) *http.Server {
	server := configuredHTTPServer(bindAddr, port, handler, cfg)
	server.ReadTimeout = max(server.ReadTimeout, cfg.GitHubStreamTimeout)
	server.WriteTimeout = max(server.WriteTimeout, cfg.GitHubStreamTimeout)
	return server
}

func serve(ctx context.Context, server *http.Server, bindAddr string, port string) error {
	server.Addr = net.JoinHostPort(bindAddr, port)
	return serveServers(ctx, []*http.Server{server})
}

func serveServers(ctx context.Context, servers []*http.Server) error {
	errCh := make(chan error, len(servers))
	for _, server := range servers {
		server := server
		go func() {
			log.Printf("gh-broker listening on %s", server.Addr)
			errCh <- server.ListenAndServe()
		}()
	}
	select {
	case err := <-errCh:
		_ = shutdownServers(servers)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return shutdownServers(servers)
	}
}

func shutdown(server *http.Server) error {
	return shutdownServers([]*http.Server{server})
}

func shutdownServers(servers []*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var errs []error
	for _, server := range servers {
		if err := server.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("shutdown server: %w", err))
		}
	}
	return errors.Join(errs...)
}
