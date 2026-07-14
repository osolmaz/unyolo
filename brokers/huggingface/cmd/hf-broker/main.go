package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/httpapi"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/endpoint"
	"github.com/osolmaz/brokerkit/serverhttp"
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
		return runAuxiliaryCommand(ctx, stdout, stderr, args)
	}
}

func runAuxiliaryCommand(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if args[0] == "policy" {
		return runPolicy(ctx, stdout, stderr, args[1:])
	}
	return exitError{code: 64, message: "usage: hf-broker [--version|version|doctor|setup|policy|client|mcp]"}
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
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: cfg.AgentEndpoint}}
	if len(cfg.Operators) > 0 {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *cfg.OperatorEndpoint})
	}
	listeners, err := endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: cfg.Development})
	if err != nil {
		return err
	}
	agentServer, err := serverhttp.New(handler, serverhttp.ProfileStreaming)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return err
	}
	bindings := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if len(cfg.Operators) > 0 {
		operatorServer, serverErr := serverhttp.New(handler.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			_ = endpoint.CloseSet(listeners)
			return serverErr
		}
		bindings = append(bindings, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	if cfg.Development {
		if err := writeReadiness(stdout, cfg, bindings); err != nil {
			_ = serverhttp.Shutdown(bindings)
			return err
		}
	}
	err = serverhttp.Serve(ctx, bindings)
	if ctx.Err() != nil && err == nil {
		_, _ = fmt.Fprintln(stderr, "hf-broker stopped")
	}
	return err
}

func writeReadiness(stdout io.Writer, cfg config.Config, bindings []serverhttp.Binding) error {
	agent, err := endpoint.Resolved(cfg.AgentEndpoint, bindings[0].Listener)
	if err != nil {
		return err
	}
	record := map[string]string{"event": "broker.ready", "agent_endpoint": agent.String()}
	if cfg.OperatorEndpoint != nil {
		operator, resolveErr := endpoint.Resolved(*cfg.OperatorEndpoint, bindings[1].Listener)
		if resolveErr != nil {
			return resolveErr
		}
		record["operator_endpoint"] = operator.String()
	}
	return json.NewEncoder(stdout).Encode(record)
}

type exitError struct {
	code    int
	message string
}

func (e exitError) Error() string {
	return e.message
}
