package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/osolmaz/brokerkit/brokers/github/internal/config"
	"github.com/osolmaz/brokerkit/brokers/github/internal/githubsurface"
	"github.com/osolmaz/brokerkit/brokers/github/internal/httpapi"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
	"github.com/osolmaz/brokerkit/endpoint"
	"github.com/osolmaz/brokerkit/serverhttp"
	"github.com/osolmaz/brokerkit/statecmd"
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
	case "policy":
		return runPolicy(stdout, stderr, args[1:])
	case "operations":
		return runOperations(stdout, args[1:])
	case "operation":
		return runOperation(ctx, stdout, args[1:])
	case "stream":
		return runStream(ctx, stdout, args[1:])
	case "mcp":
		return runMCP(ctx, os.Getenv, os.Stdin, stdout, args[1:])
	case "state":
		return statecmd.Run(ctx, args[1:], stdout, stderr)
	default:
		if found, err := runGeneratedCLI(ctx, stdout, args); found {
			return err
		}
		return fmt.Errorf("usage: gh-broker [--version|version|doctor|setup|policy|operations|operation|stream|mcp|state]")
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

func buildServers(ctx context.Context, cfg config.Config) ([]serverhttp.Binding, error) {
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
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: cfg.AgentEndpoint}}
	if cfg.OperatorSecret != "" {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *cfg.OperatorEndpoint})
	}
	listeners, err := endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: cfg.Development})
	if err != nil {
		_ = api.Close()
		return nil, err
	}
	agentServer, err := serverhttp.New(api.Handler(), serverhttp.ProfileStreaming)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		_ = api.Close()
		return nil, err
	}
	servers := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if cfg.OperatorSecret != "" {
		operatorServer, serverErr := serverhttp.New(api.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			_ = endpoint.CloseSet(listeners)
			_ = api.Close()
			return nil, serverErr
		}
		servers = append(servers, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	var closeOnce sync.Once
	for _, binding := range servers {
		binding.Server.RegisterOnShutdown(func() { closeOnce.Do(func() { _ = api.Close() }) })
	}
	return servers, nil
}

func serveServers(ctx context.Context, servers []serverhttp.Binding) error {
	return serverhttp.Serve(ctx, servers)
}
