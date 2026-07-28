package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/osolmaz/unyolo/brokers/github/internal/config"
	"github.com/osolmaz/unyolo/brokers/github/internal/githubsurface"
	"github.com/osolmaz/unyolo/brokers/github/internal/httpapi"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/deployment/component"
	"github.com/osolmaz/unyolo/internal/storage/command"
	"github.com/osolmaz/unyolo/transport/endpoint"
	"github.com/osolmaz/unyolo/transport/http/server"
)

var version = "dev"

type cliCommand func(context.Context, []string, io.Writer, io.Writer) error

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

func runWithArgs(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	if len(args) == 0 {
		return runServer(ctx)
	}
	if err, handled := runNamedCommand(ctx, args, stdout, stderr); handled {
		return err
	}
	if found, err := runGeneratedCLI(ctx, stdout, args); found {
		return err
	}
	return fmt.Errorf("usage: gh-broker [--version|version|doctor|setup|git|policy|operations|operation|stream|mcp|state]")
}

func runNamedCommand(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) (error, bool) {
	command, found := namedCommands()[args[0]]
	if !found {
		return nil, false
	}
	return command(ctx, args[1:], stdout, stderr), true
}

func namedCommands() map[string]cliCommand {
	commands := map[string]cliCommand{
		"--version": runVersionCommand,
		"version":   runVersionCommand,
		"setup": func(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
			return runSetupWithContext(ctx, stdout, stderr, args)
		},
		"git": runGitCommand,
		"doctor": func(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
			return runDoctor(ctx, stdout, stderr, args)
		},
		"policy": func(_ context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
			return runPolicy(stdout, stderr, args)
		},
		"operations": func(_ context.Context, args []string, stdout io.Writer, _ io.Writer) error {
			return runOperations(stdout, args)
		},
		"operation": func(ctx context.Context, args []string, stdout io.Writer, _ io.Writer) error {
			return runOperation(ctx, stdout, args)
		},
		"stream": func(ctx context.Context, args []string, stdout io.Writer, _ io.Writer) error {
			return runStream(ctx, stdout, args)
		},
		"mcp": func(ctx context.Context, args []string, stdout io.Writer, _ io.Writer) error {
			return runMCP(ctx, os.Getenv, os.Stdin, stdout, args)
		},
		"setup-component-probe": func(ctx context.Context, args []string, stdout io.Writer, _ io.Writer) error {
			if err := component.Probe(ctx, args); err != nil {
				return err
			}
			_, err := fmt.Fprintln(stdout, "ok")
			return err
		},
		"setup-component": func(ctx context.Context, args []string, stdout io.Writer, _ io.Writer) error {
			if len(args) != 0 {
				return errors.New("setup-component does not accept arguments")
			}
			return component.Serve(ctx, os.Stdin, stdout, component.Config{
				ComponentID: "github", ProfileAPI: "unyolo.io/github-deployment/v1",
				AllowedPaths:    []string{"/etc/gh-broker", "/var/lib/gh-broker", "/etc/systemd/system/gh-broker.service"},
				AllowedServices: []string{"gh-broker.service"}, AllowedAccounts: []string{"gh-broker"},
				AllowedGroups: []string{"gh-broker", "gh-broker-agent", "gh-broker-operator"}, BackupDirectory: "/var/lib/gh-broker/deployment-backups",
			})
		},
		"state": func(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
			return statecmd.Run(ctx, args, stdout, stderr)
		},
	}
	return commands
}

func runVersionCommand(_ context.Context, _ []string, stdout io.Writer, _ io.Writer) error {
	_, err := fmt.Fprintln(stdout, version)
	return err
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
	api, err := newGitHubAPI(ctx, cfg)
	if err != nil {
		return nil, err
	}
	listeners, err := listenGitHubEndpoints(cfg)
	if err != nil {
		_ = api.Close()
		return nil, err
	}
	servers, err := newGitHubServers(api, listeners, cfg.OperatorSecret != "")
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		_ = api.Close()
		return nil, err
	}
	registerGitHubServerShutdown(servers, api)
	return servers, nil
}

func newGitHubAPI(ctx context.Context, cfg config.Config) (*httpapi.Server, error) {
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
	return api, nil
}

func listenGitHubEndpoints(cfg config.Config) (map[string]net.Listener, error) {
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: cfg.AgentEndpoint}}
	if cfg.OperatorSecret != "" {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *cfg.OperatorEndpoint})
	}
	if cfg.GitEndpoint != nil {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "git", Endpoint: *cfg.GitEndpoint})
	}
	return endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: cfg.Development})
}

func newGitHubServers(api *httpapi.Server, listeners map[string]net.Listener, operatorEnabled bool) ([]serverhttp.Binding, error) {
	agentServer, err := serverhttp.New(api.Handler(), serverhttp.ProfileStreaming)
	if err != nil {
		return nil, err
	}
	servers := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if operatorEnabled {
		operatorServer, serverErr := serverhttp.New(api.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			return nil, serverErr
		}
		servers = append(servers, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	if gitListener := listeners["git"]; gitListener != nil {
		gitHandler, handlerErr := api.GitHandler()
		if handlerErr != nil {
			return nil, handlerErr
		}
		gitServer, serverErr := serverhttp.New(gitHandler, serverhttp.ProfileStreaming)
		if serverErr != nil {
			return nil, serverErr
		}
		servers = append(servers, serverhttp.Binding{Server: gitServer, Listener: gitListener})
	}
	return servers, nil
}

func registerGitHubServerShutdown(servers []serverhttp.Binding, api *httpapi.Server) {
	var closeOnce sync.Once
	for _, binding := range servers {
		binding.Server.RegisterOnShutdown(func() { closeOnce.Do(func() { _ = api.Close() }) })
	}
}

func serveServers(ctx context.Context, servers []serverhttp.Binding) error {
	return serverhttp.Serve(ctx, servers)
}
