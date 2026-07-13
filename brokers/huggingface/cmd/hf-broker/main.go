package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/httpapi"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

var version = "dev"

func main() {
	os.Exit(exitCodeForRun(run(), os.Stderr))
}

func exitCodeForRun(err error, stderr io.Writer) int {
	if err == nil {
		return 0
	}
	var exitErr exitError
	if errors.As(err, &exitErr) {
		if exitErr.message != "" {
			_, _ = fmt.Fprintln(stderr, exitErr.message)
		}
		return exitErr.code
	}
	_, _ = fmt.Fprintln(stderr, err)
	return 1
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runWithArgs(ctx, os.Getenv, os.Stdout, os.Stderr, os.Args[1:])
}

func runWithContext(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) error {
	return runServer(ctx, getenv, stdout, stderr)
}

func runWithArgs(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return runServer(ctx, getenv, stdout, stderr)
	}
	return runCommand(ctx, getenv, stdout, stderr, args)
}

func runCommand(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	switch args[0] {
	case "--version", "version":
		_, err := fmt.Fprintln(stdout, version)
		return err
	case "doctor":
		return runDoctor(ctx, stdout, stderr, args[1:])
	case "setup":
		return runSetup(ctx, stdout, stderr, args[1:])
	case "client":
		return runClientCommand(ctx, getenv, stdout, stderr, args[1:])
	case "mcp":
		return runMCP(ctx, getenv, os.Stdin, stdout, stderr, args[1:])
	case "__doctor-isolation-probe":
		return runDoctorIsolationProbe(stdout, stderr, args[1:])
	default:
		return exitError{code: 64, message: "usage: hf-broker [--version|version|doctor|setup|client|mcp]"}
	}
}

func runClientCommand(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer, args []string) error {
	if len(args) >= 1 && args[0] == "grant" {
		return runGrantClientFromEnv(ctx, getenv, stdout, stderr, args[1:])
	}
	return runAgentClient(ctx, getenv, stdout, stderr, args)
}

func runServer(ctx context.Context, getenv func(string) string, stdout, stderr io.Writer) error {
	cfg, err := config.Load(getenv)
	if err != nil {
		return err
	}
	pol, err := policy.LoadFile(cfg.ScopeFile)
	if err != nil {
		return err
	}
	auditRecorder := audit.New(stdout)
	handler, err := httpapi.New(httpapi.Options{
		Config:                cfg,
		Scope:                 pol,
		Audit:                 auditRecorder,
		Context:               ctx,
		UpstreamBaseURL:       cfg.UpstreamHubURL,
		UpstreamRouterBaseURL: cfg.UpstreamRouterURL,
		OperatorAudit:         auditRecorder,
	})
	if err != nil {
		return err
	}
	defer func() { _ = handler.Close() }()
	servers := []*http.Server{{
		Addr:              net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.Port)),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}}
	if len(cfg.Operators) > 0 {
		servers = append(servers, &http.Server{
			Addr:    net.JoinHostPort(cfg.OperatorBindAddr, strconv.Itoa(cfg.OperatorPort)),
			Handler: handler.OperatorHandler(), ReadHeaderTimeout: 10 * time.Second,
		})
	}
	return serveServersWithContext(ctx, servers, stderr)
}

func serveServersWithContext(ctx context.Context, servers []*http.Server, stderr io.Writer) error {
	errs := make(chan error, len(servers))
	for _, server := range servers {
		go func(server *http.Server) { errs <- server.ListenAndServe() }(server)
	}
	select {
	case <-ctx.Done():
		if err := shutdownServers(servers); err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "hf-broker stopped")
		return nil
	case err := <-errs:
		_ = shutdownServers(servers)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func shutdownServers(servers []*http.Server) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var errs []error
	for _, server := range servers {
		if err := server.Shutdown(shutdownCtx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	return e.message
}
