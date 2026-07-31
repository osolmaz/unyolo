package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/approval/notification"
	unyolotelegram "github.com/osolmaz/unyolo/approval/notifier/telegram"
	"github.com/osolmaz/unyolo/authorization/admission"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/catalog"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/routes"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/unyolo/internal/config/secretfile"
	"github.com/osolmaz/unyolo/internal/slicex"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/telemetry/audit"
	"github.com/osolmaz/unyolo/transport/endpoint"
	"github.com/osolmaz/unyolo/transport/http/server"
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
	tlsCertificate   string
	tlsPrivateKey    string
	networkExposure  bool
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
	if err := waitForServerHelper(ctx, server); err != nil {
		_ = server.Close()
		return serveOptions{}, nil, err
	}
	return opts, server, nil
}

func listenServeBindings(opts serveOptions, server *routes.Server) ([]serverhttp.Binding, error) {
	operatorHandler := server.OperatorHandler()
	listenerSpecs := serveListenerSpecs(opts, operatorHandler != nil)
	tlsConfig, err := sudoServerTLSConfig(opts)
	if err != nil {
		return nil, err
	}
	listeners, err := endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: opts.development, TLSConfig: tlsConfig})
	if err != nil {
		return nil, err
	}
	bindings, err := newServeBindings(server.Handler(), operatorHandler, listeners)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return nil, err
	}
	return bindings, nil
}

func serveListenerSpecs(opts serveOptions, withOperator bool) []endpoint.Named {
	values := []endpoint.Named{{Name: "agent", Endpoint: opts.agentEndpoint}}
	if withOperator {
		values = append(values, endpoint.Named{Name: "operator", Endpoint: *opts.operatorEndpoint})
	}
	return values
}

func newServeBindings(agentHandler, operatorHandler http.Handler, listeners map[string]net.Listener) ([]serverhttp.Binding, error) {
	agentServer, err := serverhttp.New(agentHandler, serverhttp.ProfileStreaming)
	if err != nil {
		return nil, err
	}
	bindings := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if operatorHandler == nil {
		return bindings, nil
	}
	operatorServer, err := serverhttp.New(operatorHandler, serverhttp.ProfileOperator)
	if err != nil {
		return nil, err
	}
	return append(bindings, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]}), nil
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
	flags.StringVar(&opts.stateDirectory, "state", "", "unYOLO state directory")
	flags.StringVar(&opts.helperSocket, "helper-socket", "", "privileged helper Unix socket")
	var agentEndpoint, operatorEndpoint string
	flags.StringVar(&agentEndpoint, "agent-endpoint", "", "agent endpoint URI")
	flags.StringVar(&operatorEndpoint, "operator-endpoint", "", "operator endpoint URI")
	flags.StringVar(&opts.telegramToken, "telegram-token-file", "", "private Telegram bot token file")
	flags.Int64Var(&opts.telegramChatID, "telegram-chat-id", 0, "Telegram approval chat id")
	flags.StringVar(&opts.admissionConfig, "admission-config", "", "absolute admission limits JSON")
	flags.StringVar(&opts.tlsCertificate, "tls-cert-file", "", "TLS server certificate")
	flags.StringVar(&opts.tlsPrivateKey, "tls-key-file", "", "TLS server private key")
	var networkExposure string
	flags.StringVar(&networkExposure, "network-exposure", "", "set to allow for reviewed network listeners")
	flags.BoolVar(&opts.development, "development", false, "enable foreground development path rules")
	if err := flags.Parse(args); err != nil {
		return serveOptions{}, err
	}
	if err := validateServeRequiredFlags(flags.NArg(), opts, agentEndpoint); err != nil {
		return serveOptions{}, err
	}
	if networkExposure != "" && networkExposure != "allow" {
		return serveOptions{}, errors.New("--network-exposure must be allow when set")
	}
	opts.networkExposure = networkExposure == "allow"
	parseOptions := endpoint.ParseOptions{AllowNetworkTCP: opts.networkExposure, AllowNetworkTLS: opts.networkExposure}
	parsedAgent, err := endpoint.Parse(agentEndpoint, parseOptions)
	if err != nil {
		return serveOptions{}, fmt.Errorf("agent endpoint: %w", err)
	}
	opts.agentEndpoint = parsedAgent
	if err := parseServeOperatorEndpoint(&opts, operatorEndpoint, parsedAgent, parseOptions); err != nil {
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

func parseServeOperatorEndpoint(opts *serveOptions, operatorEndpoint string, agent endpoint.Endpoint, parseOptions endpoint.ParseOptions) error {
	if opts.operatorSecrets == "" {
		return nil
	}
	parsedOperator, err := endpoint.Parse(operatorEndpoint, parseOptions)
	if err != nil {
		return fmt.Errorf("operator endpoint: %w", err)
	}
	if parsedOperator.String() == agent.String() {
		return errors.New("agent and operator listeners must differ")
	}
	opts.operatorEndpoint = &parsedOperator
	return nil
}

func sudoServerTLSConfig(opts serveOptions) (*tls.Config, error) {
	if opts.tlsCertificate == "" {
		return nil, nil
	}
	return endpoint.ServerTLSConfig(opts.tlsCertificate, opts.tlsPrivateKey)
}

func validateServeSecurityOptions(opts serveOptions) error {
	if !filepath.IsAbs(opts.helperSocket) {
		return errors.New("helper socket path must be absolute")
	}
	if err := validateServeApproverOptions(opts); err != nil {
		return err
	}
	needsTLS := serveNeedsTLS(opts)
	if needsTLS != (opts.tlsCertificate != "" && opts.tlsPrivateKey != "") {
		return errors.New("--tls-cert-file and --tls-key-file are required exactly for TLS listeners")
	}
	if !needsTLS {
		return nil
	}
	_, err := sudoServerTLSConfig(opts)
	return err
}

func validateServeApproverOptions(opts serveOptions) error {
	if (opts.telegramToken == "") != (opts.telegramChatID == 0) {
		return errors.New("telegram token file and chat id must be configured together")
	}
	if opts.operatorSecrets == "" && opts.telegramToken == "" {
		return errors.New("an operator credential or Telegram approval channel is required")
	}
	return nil
}

func serveNeedsTLS(opts serveOptions) bool {
	if opts.agentEndpoint.Scheme() == endpoint.SchemeTLS {
		return true
	}
	return opts.operatorEndpoint != nil && opts.operatorEndpoint.Scheme() == endpoint.SchemeTLS
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
	clients, err := secretfile.ParseWithOptions(opts.secretsPath, secretfile.ParseOptions{AllowEmpty: true})
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
	for _, path := range []string{opts.policyPath, opts.catalogPath, opts.secretsPath, opts.operatorSecrets, opts.telegramToken, opts.admissionConfig, opts.tlsCertificate, opts.tlsPrivateKey} {
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

func loadTelegramNotifier(opts serveOptions) (*unyolotelegram.Client, error) {
	if opts.telegramToken == "" {
		return nil, nil
	}
	data, err := os.ReadFile(opts.telegramToken) // #nosec G304 -- validated operator-configured root-owned path.
	if err != nil {
		return nil, err
	}
	return unyolotelegram.NewWithOptions(strings.TrimSpace(string(data)), opts.telegramChatID, nil, "", unyolotelegram.Options{
		Route: unyolotelegram.RouteSudo,
	})
}

func notifierDependencies(notifier *unyolotelegram.Client) (approvalnotify.Notifier, routes.DecisionPoller) {
	if notifier == nil {
		return nil, nil
	}
	return notifier, nil
}

const (
	helperStartupTimeout  = 5 * time.Second
	helperStartupInterval = 50 * time.Millisecond
)

func waitForServerHelper(ctx context.Context, server *routes.Server) error {
	readyCtx, cancel := context.WithTimeout(ctx, helperStartupTimeout)
	defer cancel()
	var lastErr error
	for {
		lastErr = serverHelperReady(readyCtx, server)
		if lastErr == nil {
			return nil
		}
		timer := time.NewTimer(helperStartupInterval)
		select {
		case <-readyCtx.Done():
			timer.Stop()
			return errors.Join(lastErr, readyCtx.Err())
		case <-timer.C:
		}
	}
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
