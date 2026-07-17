package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/admission"
	"github.com/osolmaz/brokerkit/approvalnotify"
	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/routes"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/endpoint"
	"github.com/osolmaz/brokerkit/internal/slicex"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/secretfile"
	"github.com/osolmaz/brokerkit/serverhttp"
	"github.com/osolmaz/brokerkit/state"
)

type serveOptions struct {
	policyPath       string
	catalogPath      string
	secretsPath      string
	operatorSecrets  string
	stateDirectory   string
	helperSocket     string
	agentEndpoint    endpoint.Endpoint
	operatorEndpoint *endpoint.Endpoint
	telegramToken    string
	telegramChatID   int64
	admissionConfig  string
	development      bool
}

func runServe(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return runServeWith(ctx, args, stdout, stderr, os.Geteuid, buildServer, serveHTTP)
}

func runServeWith(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, geteuid func() int,
	build func(serveOptions, io.Writer) (*routes.Server, error), serve func(context.Context, []serverhttp.Binding) error) error {
	if err := validateServeRuntime(geteuid, build, serve); err != nil {
		return err
	}
	if err := rejectRootFrontend(geteuid); err != nil {
		return err
	}
	opts, server, err := buildReadyServer(ctx, args, stderr, build)
	if err != nil {
		return err
	}
	defer func() { _ = server.Close() }()
	server.Start(ctx)
	bindings, err := listenServeBindings(opts, server)
	if err != nil {
		return err
	}
	printServeBindings(stdout, bindings)
	return serve(ctx, bindings)
}

func validateServeRuntime(geteuid func() int, build func(serveOptions, io.Writer) (*routes.Server, error), serve func(context.Context, []serverhttp.Binding) error) error {
	if geteuid == nil || build == nil || serve == nil {
		return errors.New("serve runtime dependencies are required")
	}
	return nil
}

func rejectRootFrontend(geteuid func() int) error {
	if geteuid() == 0 {
		return errors.New("frontend must run as a dedicated non-root user")
	}
	return nil
}

func buildReadyServer(ctx context.Context, args []string, stderr io.Writer, build func(serveOptions, io.Writer) (*routes.Server, error)) (serveOptions, *routes.Server, error) {
	opts, err := parseServeOptions(args)
	if err != nil {
		return serveOptions{}, nil, err
	}
	server, err := build(opts, stderr)
	if err != nil {
		return serveOptions{}, nil, err
	}
	if err := serverHelperReady(ctx, server); err != nil {
		_ = server.Close()
		return serveOptions{}, nil, err
	}
	return opts, server, nil
}

func listenServeBindings(opts serveOptions, server *routes.Server) ([]serverhttp.Binding, error) {
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: opts.agentEndpoint}}
	if server.OperatorHandler() != nil {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *opts.operatorEndpoint})
	}
	listeners, err := endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: opts.development})
	if err != nil {
		return nil, err
	}
	agentServer, err := serverhttp.New(server.Handler(), serverhttp.ProfileStreaming)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return nil, err
	}
	bindings := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if server.OperatorHandler() != nil {
		operatorServer, serverErr := serverhttp.New(server.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			_ = endpoint.CloseSet(listeners)
			return nil, serverErr
		}
		bindings = append(bindings, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	return bindings, nil
}

func printServeBindings(stdout io.Writer, bindings []serverhttp.Binding) {
	for _, value := range bindings {
		_, _ = fmt.Fprintf(stdout, "sudo-broker listening on %s\n", value.Listener.Addr())
	}
}

func parseServeOptions(args []string) (serveOptions, error) {
	var opts serveOptions
	flags := flag.NewFlagSet("sudo-broker serve", flag.ContinueOnError)
	flags.StringVar(&opts.policyPath, "policy", "", "root-owned policy JSON")
	flags.StringVar(&opts.catalogPath, "catalog", "", "root-owned command catalog")
	flags.StringVar(&opts.secretsPath, "secrets", "", "named client secret file")
	flags.StringVar(&opts.operatorSecrets, "operator-secrets", "", "named operator secret file")
	flags.StringVar(&opts.stateDirectory, "state", "", "BrokerKit state directory")
	flags.StringVar(&opts.helperSocket, "helper-socket", "", "privileged helper Unix socket")
	var agentEndpoint, operatorEndpoint string
	flags.StringVar(&agentEndpoint, "agent-endpoint", "", "agent endpoint URI")
	flags.StringVar(&operatorEndpoint, "operator-endpoint", "", "operator endpoint URI")
	flags.StringVar(&opts.telegramToken, "telegram-token-file", "", "private Telegram bot token file")
	flags.Int64Var(&opts.telegramChatID, "telegram-chat-id", 0, "Telegram approval chat id")
	flags.StringVar(&opts.admissionConfig, "admission-config", "", "absolute admission limits JSON")
	flags.BoolVar(&opts.development, "development", false, "enable foreground development path rules")
	if err := flags.Parse(args); err != nil {
		return serveOptions{}, err
	}
	if err := validateServeRequiredFlags(flags.NArg(), opts, agentEndpoint); err != nil {
		return serveOptions{}, err
	}
	parsedAgent, err := endpoint.Parse(agentEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return serveOptions{}, fmt.Errorf("agent endpoint: %w", err)
	}
	opts.agentEndpoint = parsedAgent
	if err := parseServeOperatorEndpoint(&opts, operatorEndpoint, parsedAgent); err != nil {
		return serveOptions{}, err
	}
	if err := validateServeSecurityOptions(opts); err != nil {
		return serveOptions{}, err
	}
	return opts, nil
}

func validateServeRequiredFlags(extraArgs int, opts serveOptions, agentEndpoint string) error {
	if extraArgs != 0 || opts.policyPath == "" || opts.catalogPath == "" || opts.secretsPath == "" ||
		opts.stateDirectory == "" || opts.helperSocket == "" || agentEndpoint == "" {
		return errors.New("--policy, --catalog, --secrets, --state, --helper-socket, and --agent-endpoint are required")
	}
	return nil
}

func parseServeOperatorEndpoint(opts *serveOptions, operatorEndpoint string, agent endpoint.Endpoint) error {
	if opts.operatorSecrets == "" {
		return nil
	}
	parsedOperator, err := endpoint.Parse(operatorEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return fmt.Errorf("operator endpoint: %w", err)
	}
	if parsedOperator.String() == agent.String() {
		return errors.New("agent and operator listeners must differ")
	}
	opts.operatorEndpoint = &parsedOperator
	return nil
}

func validateServeSecurityOptions(opts serveOptions) error {
	if !filepath.IsAbs(opts.helperSocket) {
		return errors.New("helper socket path must be absolute")
	}
	if (opts.telegramToken == "") != (opts.telegramChatID == 0) {
		return errors.New("telegram token file and chat id must be configured together")
	}
	if opts.operatorSecrets == "" && opts.telegramToken == "" {
		return errors.New("an operator credential or Telegram approval channel is required")
	}
	return nil
}

func buildServer(opts serveOptions, stderr io.Writer) (*routes.Server, error) {
	return buildServerWithValidator(opts, stderr, hostcheck.ValidateRootFile)
}

func buildServerWithValidator(opts serveOptions, stderr io.Writer, validateRootFile func(string) error) (*routes.Server, error) {
	if validateRootFile == nil {
		return nil, errors.New("security-sensitive file validator is required")
	}
	if err := validateServeInputFiles(opts, validateRootFile); err != nil {
		return nil, err
	}
	loaded, err := loadServeInputs(opts)
	if err != nil {
		return nil, err
	}
	database, err := state.Open(context.Background(), opts.stateDirectory, state.Options{})
	if err != nil {
		return nil, err
	}
	helper := &executorclient.Client{SocketPath: opts.helperSocket, Timeout: 10 * time.Second}
	notifier, err := loadTelegramNotifier(opts)
	if err != nil {
		_ = database.Close()
		return nil, err
	}
	notifierService, poller := notifierDependencies(notifier)
	server, err := routes.New(routes.Options{
		Policy: loaded.policy, Catalog: loaded.snapshot, Database: database,
		Identities: plan.SystemIdentityResolver{}, Helper: helper, ClientSecrets: loaded.clients, OperatorSecrets: loaded.operators,
		Notifier: notifierService, Poller: poller, Audit: audit.New(stderr), OperatorConfigured: len(loaded.operators) > 0,
		Admission: loaded.admission,
	})
	if err != nil {
		_ = database.Close()
	}
	return server, err
}

type serveInputs struct {
	snapshot  *catalog.Snapshot
	policy    *corepolicy.Policy
	clients   map[string]string
	operators map[string]string
	admission admission.Config
}

func loadServeInputs(opts serveOptions) (serveInputs, error) {
	snapshot, err := catalog.Load(opts.catalogPath)
	if err != nil {
		return serveInputs{}, err
	}
	policy, err := corepolicy.LoadFile(opts.policyPath, sudopolicy.Registry(snapshot))
	if err != nil {
		return serveInputs{}, err
	}
	clients, err := secretfile.Parse(opts.secretsPath)
	if err != nil {
		return serveInputs{}, err
	}
	admissionConfig, err := admission.LoadFile(opts.admissionConfig, slicex.Keys(clients))
	if err != nil {
		return serveInputs{}, err
	}
	operators, err := loadOperatorSecrets(opts.operatorSecrets)
	if err != nil {
		return serveInputs{}, err
	}
	return serveInputs{snapshot: snapshot, policy: policy, clients: clients, operators: operators, admission: admissionConfig}, nil
}

func validateServeInputFiles(opts serveOptions, validateRootFile func(string) error) error {
	for _, path := range []string{opts.policyPath, opts.catalogPath, opts.secretsPath, opts.operatorSecrets, opts.telegramToken, opts.admissionConfig} {
		if path == "" {
			continue
		}
		if err := validateRootFile(path); err != nil {
			return fmt.Errorf("security-sensitive file %s is unsafe: %w", path, err)
		}
	}
	return nil
}

func loadOperatorSecrets(path string) (map[string]string, error) {
	if path == "" {
		return map[string]string{}, nil
	}
	return secretfile.Parse(path)
}

func loadTelegramNotifier(opts serveOptions) (*bktelegram.Client, error) {
	if opts.telegramToken == "" {
		return nil, nil
	}
	data, err := os.ReadFile(opts.telegramToken) // #nosec G304 -- validated operator-configured root-owned path.
	if err != nil {
		return nil, err
	}
	return bktelegram.NewWithOptions(strings.TrimSpace(string(data)), opts.telegramChatID, nil, "", bktelegram.Options{
		Route: bktelegram.RouteSudo,
	})
}

func notifierDependencies(notifier *bktelegram.Client) (approvalnotify.Notifier, routes.DecisionPoller) {
	if notifier == nil {
		return nil, nil
	}
	return notifier, nil
}

func serverHelperReady(ctx context.Context, server *routes.Server) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/readyz", http.NoBody)
	if err != nil {
		return err
	}
	recorder := &statusRecorder{header: make(http.Header)}
	server.Handler().ServeHTTP(recorder, request)
	if recorder.status != http.StatusOK {
		return errors.New("privileged helper is not ready")
	}
	return nil
}

type statusRecorder struct {
	header http.Header
	status int
}

func (r *statusRecorder) Header() http.Header { return r.header }
func (r *statusRecorder) Write(value []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return len(value), nil
}
func (r *statusRecorder) WriteHeader(status int) { r.status = status }

func serveHTTP(ctx context.Context, bindings []serverhttp.Binding) error {
	return serverhttp.Serve(ctx, bindings)
}
