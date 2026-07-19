package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/httpapi"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/endpoint"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/providercredential"
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
	return runCommandInput(ctx, getenv, os.Stdin, stdout, stderr, args)
}

func runCommandInput(ctx context.Context, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	run, found := commandRunners[args[0]]
	if !found {
		return exitError{code: 64, message: "usage: hf-broker [--version|version|credential|doctor|setup|git|policy|client|mcp|state]"}
	}
	return run(commandContext{ctx: ctx, getenv: getenv, stdin: stdin, stdout: stdout, stderr: stderr}, args[1:])
}

type commandContext struct {
	ctx            context.Context
	getenv         func(string) string
	stdin          io.Reader
	stdout, stderr io.Writer
}

var commandRunners = map[string]func(commandContext, []string) error{
	"--version":                runVersionCommand,
	"version":                  runVersionCommand,
	"credential":               runCredentialCommand,
	"doctor":                   runDoctorCommand,
	"setup":                    runSetupCommand,
	"git":                      runGitCommand,
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

func runCredentialCommand(command commandContext, args []string) error {
	return runCredential(command, args, defaultCredentialDependencies())
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
	return runMCP(command.ctx, command.getenv, command.stdin, command.stdout, command.stderr, args)
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
	var credential *providercredential.Service
	if !cfg.Development {
		credential, err = activeCredentialService(ctx, cfg)
		if err != nil {
			return nil, err
		}
	}
	return httpapi.New(httpapi.Options{Config: cfg, Scope: pol, Audit: auditRecorder, Context: ctx,
		UpstreamBaseURL: cfg.UpstreamHubURL, UpstreamRouterBaseURL: cfg.UpstreamRouterURL, OperatorAudit: auditRecorder,
		Credential: credential})
}

func activeCredentialService(ctx context.Context, cfg config.Config) (*providercredential.Service, error) {
	status, err := loadActiveCredentialStatus(cfg.HFTokenFile)
	if err != nil {
		return nil, err
	}
	snapshot, err := inspectActiveCredential(ctx, cfg, activeCredentialHTTPClient(cfg.HFTimeout), credentialGeneration(status))
	if err != nil {
		return nil, err
	}
	if status != nil && snapshot.FingerprintSHA256 != status.Snapshot.FingerprintSHA256 {
		return nil, errors.New("HF credential metadata does not match the active credential; run hf-broker credential repair")
	}
	return providercredential.NewService(snapshot)
}

func activeCredentialHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func credentialGeneration(status *credentialStatus) uint64 {
	if status != nil {
		return status.Snapshot.Generation
	}
	return 1
}

func inspectActiveCredential(ctx context.Context, cfg config.Config, client *http.Client, generation uint64) (providercredential.Snapshot, error) {
	secret, err := providercredential.NewSecret([]byte(cfg.HFToken))
	if err != nil {
		return providercredential.Snapshot{}, errors.New("HF provider credential is unavailable")
	}
	defer secret.Clear()
	snapshot, err := (credentialauth.Adapter{Inspector: credentialauth.Inspector{BaseURL: cfg.UpstreamHubURL, Client: client}, Generation: generation}).Inspect(ctx, secret)
	if err != nil {
		return providercredential.Snapshot{}, fmt.Errorf("inspect HF provider credential: %w", err)
	}
	return snapshot, nil
}

func loadActiveCredentialStatus(tokenFile string) (*credentialStatus, error) {
	tokenFile = strings.TrimSpace(tokenFile)
	if tokenFile == "" {
		return nil, nil
	}
	path := filepath.Join(filepath.Dir(tokenFile), credentialStatusFileName)
	data, found, err := readActiveCredentialStatus(path)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return decodeActiveCredentialStatus(data)
}

func readActiveCredentialStatus(path string) ([]byte, bool, error) {
	file, err := os.Open(path) // #nosec G304 -- derived from the operator-configured credential file.
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, errors.New("HF credential metadata is unavailable; run hf-broker credential repair")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxCredentialStatusBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maxCredentialStatusBytes {
		return nil, false, errors.New("HF credential metadata is invalid; run hf-broker credential repair")
	}
	return data, true, nil
}

func decodeActiveCredentialStatus(data []byte) (*credentialStatus, error) {
	var status credentialStatus
	if strictjson.Decode(data, &status, true) != nil || status.Status != "valid" {
		return nil, errors.New("HF credential metadata is invalid; run hf-broker credential repair")
	}
	normalized, err := providercredential.Normalize(status.Snapshot)
	if err != nil || normalized.Provider != "huggingface" || normalized.CredentialKind != "fine_grained_user_token" ||
		normalized.CapabilityDigest != status.Snapshot.CapabilityDigest {
		return nil, errors.New("HF credential metadata is invalid; run hf-broker credential repair")
	}
	status.Snapshot = normalized
	return &status, nil
}

func buildServerBindings(handler *httpapi.Server, cfg config.Config) ([]serverhttp.Binding, error) {
	listeners, err := listenServerEndpoints(cfg)
	if err != nil {
		return nil, err
	}
	bindings, err := newServerBindings(handler, cfg, listeners)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return nil, err
	}
	return bindings, nil
}

func listenServerEndpoints(cfg config.Config) (map[string]net.Listener, error) {
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: cfg.AgentEndpoint}}
	if len(cfg.Operators) > 0 {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *cfg.OperatorEndpoint})
	}
	if cfg.GitEndpoint != nil {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "git", Endpoint: *cfg.GitEndpoint})
	}
	return endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: cfg.Development})
}

func newServerBindings(handler *httpapi.Server, cfg config.Config, listeners map[string]net.Listener) ([]serverhttp.Binding, error) {
	agentServer, err := serverhttp.New(handler, serverhttp.ProfileStreaming)
	if err != nil {
		return nil, err
	}
	bindings := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if len(cfg.Operators) > 0 {
		operatorServer, serverErr := serverhttp.New(handler.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			return nil, serverErr
		}
		bindings = append(bindings, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	if gitListener := listeners["git"]; gitListener != nil {
		gitHandler, handlerErr := handler.GitHandler()
		if handlerErr != nil {
			return nil, handlerErr
		}
		gitServer, serverErr := serverhttp.New(gitHandler, serverhttp.ProfileStreaming)
		if serverErr != nil {
			return nil, serverErr
		}
		bindings = append(bindings, serverhttp.Binding{Server: gitServer, Listener: gitListener})
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
	if cfg.GitEndpoint != nil {
		gitIndex := len(bindings) - 1
		git, resolveErr := endpoint.Resolved(*cfg.GitEndpoint, bindings[gitIndex].Listener)
		if resolveErr != nil {
			return resolveErr
		}
		record["git_endpoint"] = git.String()
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
