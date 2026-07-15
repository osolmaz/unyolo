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
	"github.com/osolmaz/brokerkit/statecmd"
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
	run, found := commandRunners[args[0]]
	if !found {
		return exitError{code: 64, message: "usage: hf-broker [--version|version|doctor|setup|policy|client|mcp|state]"}
	}
	return run(commandContext{ctx: ctx, getenv: getenv, stdout: stdout, stderr: stderr}, args[1:])
}

type commandContext struct {
	ctx            context.Context
	getenv         func(string) string
	stdout, stderr io.Writer
}

var commandRunners = map[string]func(commandContext, []string) error{
	"--version":                runVersionCommand,
	"version":                  runVersionCommand,
	"doctor":                   runDoctorCommand,
	"setup":                    runSetupCommand,
	"policy":                   runPolicyCommand,
	"client":                   runClientTopLevelCommand,
	"mcp":                      runMCPCommand,
	"state":                    runStateCommand,
	"__doctor-isolation-probe": runIsolationProbeCommand,
}

func runVersionCommand(command commandContext, _ []string) error {
	_, err := fmt.Fprintln(command.stdout, version)
	return err
}

func runDoctorCommand(command commandContext, args []string) error {
	return runDoctor(command.ctx, command.stdout, command.stderr, args)
}

func runSetupCommand(command commandContext, args []string) error {
	return runSetup(command.ctx, command.stdout, command.stderr, args)
}

func runPolicyCommand(command commandContext, args []string) error {
	return runPolicy(command.ctx, command.stdout, command.stderr, args)
}

func runClientTopLevelCommand(command commandContext, args []string) error {
	return runClientCommand(command.ctx, command.getenv, command.stdout, command.stderr, args)
}

func runMCPCommand(command commandContext, args []string) error {
	return runMCP(command.ctx, command.getenv, os.Stdin, command.stdout, command.stderr, args)
}

func runStateCommand(command commandContext, args []string) error {
	return statecmd.Run(command.ctx, args, command.stdout, command.stderr)
}

func runIsolationProbeCommand(command commandContext, args []string) error {
	return runDoctorIsolationProbe(command.stdout, command.stderr, args)
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
	handler, err := buildHTTPHandler(ctx, stdout, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = handler.Close() }()
	bindings, err := buildServerBindings(handler, cfg)
	if err != nil {
		return err
	}
	if err := writeDevelopmentReadiness(stdout, cfg, bindings); err != nil {
		_ = serverhttp.Shutdown(bindings)
		return err
	}
	err = serverhttp.Serve(ctx, bindings)
	if ctx.Err() != nil && err == nil {
		_, _ = fmt.Fprintln(stderr, "hf-broker stopped")
	}
	return err
}

func writeDevelopmentReadiness(stdout io.Writer, cfg config.Config, bindings []serverhttp.Binding) error {
	if !cfg.Development {
		return nil
	}
	return writeReadiness(stdout, cfg, bindings)
}

func buildHTTPHandler(ctx context.Context, stdout io.Writer, cfg config.Config) (*httpapi.Server, error) {
	pol, err := policy.LoadFile(cfg.ScopeFile)
	if err != nil {
		return nil, err
	}
	auditRecorder := audit.New(stdout)
	return httpapi.New(httpapi.Options{Config: cfg, Scope: pol, Audit: auditRecorder, Context: ctx,
		UpstreamBaseURL: cfg.UpstreamHubURL, UpstreamRouterBaseURL: cfg.UpstreamRouterURL, OperatorAudit: auditRecorder})
}

func buildServerBindings(handler *httpapi.Server, cfg config.Config) ([]serverhttp.Binding, error) {
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: cfg.AgentEndpoint}}
	if len(cfg.Operators) > 0 {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *cfg.OperatorEndpoint})
	}
	listeners, err := endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: cfg.Development})
	if err != nil {
		return nil, err
	}
	agentServer, err := serverhttp.New(handler, serverhttp.ProfileStreaming)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return nil, err
	}
	bindings := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if len(cfg.Operators) > 0 {
		operatorServer, serverErr := serverhttp.New(handler.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			_ = endpoint.CloseSet(listeners)
			return nil, serverErr
		}
		bindings = append(bindings, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	return bindings, nil
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
