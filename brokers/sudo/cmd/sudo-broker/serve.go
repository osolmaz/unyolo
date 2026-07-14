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

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/routes"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/endpoint"
	"github.com/osolmaz/brokerkit/notify"
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
	development      bool
}

func runServe(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return runServeWith(ctx, args, stdout, stderr, os.Geteuid, buildServer, serveHTTP)
}

func runServeWith(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, geteuid func() int,
	build func(serveOptions, io.Writer) (*routes.Server, error), serve func(context.Context, []serverhttp.Binding) error) error {
	if geteuid == nil || build == nil || serve == nil {
		return errors.New("serve runtime dependencies are required")
	}
	if geteuid() == 0 {
		return errors.New("frontend must run as a dedicated non-root user")
	}
	opts, err := parseServeOptions(args)
	if err != nil {
		return err
	}
	server, err := build(opts, stderr)
	if err != nil {
		return err
	}
	if err := serverHelperReady(ctx, server); err != nil {
		_ = server.Close()
		return err
	}
	defer func() { _ = server.Close() }()
	server.Start(ctx)
	listenerSpecs := []endpoint.Named{{Name: "agent", Endpoint: opts.agentEndpoint}}
	if server.OperatorHandler() != nil {
		listenerSpecs = append(listenerSpecs, endpoint.Named{Name: "operator", Endpoint: *opts.operatorEndpoint})
	}
	listeners, err := endpoint.ListenSet(listenerSpecs, endpoint.ListenOptions{Development: opts.development})
	if err != nil {
		return err
	}
	agentServer, err := serverhttp.New(server.Handler(), serverhttp.ProfileStreaming)
	if err != nil {
		_ = endpoint.CloseSet(listeners)
		return err
	}
	bindings := []serverhttp.Binding{{Server: agentServer, Listener: listeners["agent"]}}
	if server.OperatorHandler() != nil {
		operatorServer, serverErr := serverhttp.New(server.OperatorHandler(), serverhttp.ProfileOperator)
		if serverErr != nil {
			_ = endpoint.CloseSet(listeners)
			return serverErr
		}
		bindings = append(bindings, serverhttp.Binding{Server: operatorServer, Listener: listeners["operator"]})
	}
	for _, value := range bindings {
		_, _ = fmt.Fprintf(stdout, "sudo-broker listening on %s\n", value.Listener.Addr())
	}
	return serve(ctx, bindings)
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
	flags.BoolVar(&opts.development, "development", false, "enable foreground development path rules")
	if err := flags.Parse(args); err != nil {
		return serveOptions{}, err
	}
	if flags.NArg() != 0 || opts.policyPath == "" || opts.catalogPath == "" || opts.secretsPath == "" || opts.stateDirectory == "" || opts.helperSocket == "" || agentEndpoint == "" {
		return serveOptions{}, errors.New("--policy, --catalog, --secrets, --state, --helper-socket, and --agent-endpoint are required")
	}
	parsedAgent, err := endpoint.Parse(agentEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return serveOptions{}, fmt.Errorf("agent endpoint: %w", err)
	}
	opts.agentEndpoint = parsedAgent
	if opts.operatorSecrets != "" {
		parsedOperator, parseErr := endpoint.Parse(operatorEndpoint, endpoint.ParseOptions{})
		if parseErr != nil {
			return serveOptions{}, fmt.Errorf("operator endpoint: %w", parseErr)
		}
		if parsedOperator.String() == parsedAgent.String() {
			return serveOptions{}, errors.New("agent and operator listeners must differ")
		}
		opts.operatorEndpoint = &parsedOperator
	}
	if !filepath.IsAbs(opts.helperSocket) {
		return serveOptions{}, errors.New("helper socket path must be absolute")
	}
	if (opts.telegramToken == "") != (opts.telegramChatID == 0) {
		return serveOptions{}, errors.New("telegram token file and chat id must be configured together")
	}
	if opts.operatorSecrets == "" && opts.telegramToken == "" {
		return serveOptions{}, errors.New("an operator credential or Telegram approval channel is required")
	}
	return opts, nil
}

func buildServer(opts serveOptions, stderr io.Writer) (*routes.Server, error) {
	return buildServerWithValidator(opts, stderr, hostcheck.ValidateRootFile)
}

func buildServerWithValidator(opts serveOptions, stderr io.Writer, validateRootFile func(string) error) (*routes.Server, error) {
	if validateRootFile == nil {
		return nil, errors.New("security-sensitive file validator is required")
	}
	for _, path := range []string{opts.policyPath, opts.catalogPath, opts.secretsPath, opts.operatorSecrets, opts.telegramToken} {
		if path != "" {
			if err := validateRootFile(path); err != nil {
				return nil, fmt.Errorf("security-sensitive file %s is unsafe: %w", path, err)
			}
		}
	}
	snapshot, err := catalog.Load(opts.catalogPath)
	if err != nil {
		return nil, err
	}
	policy, err := corepolicy.LoadFile(opts.policyPath, sudopolicy.Registry(snapshot))
	if err != nil {
		return nil, err
	}
	clients, err := secretfile.Parse(opts.secretsPath)
	if err != nil {
		return nil, err
	}
	operators := map[string]string{}
	if opts.operatorSecrets != "" {
		operators, err = secretfile.Parse(opts.operatorSecrets)
		if err != nil {
			return nil, err
		}
	}
	database, err := state.Open(context.Background(), opts.stateDirectory, state.Options{})
	if err != nil {
		return nil, err
	}
	helper := &executorclient.Client{SocketPath: opts.helperSocket, Timeout: 10 * time.Second}
	var notifier *bktelegram.Client
	if opts.telegramToken != "" {
		data, err := os.ReadFile(opts.telegramToken) // #nosec G304 -- validated operator-configured root-owned path.
		if err != nil {
			return nil, err
		}
		notifier, err = bktelegram.NewWithOptions(strings.TrimSpace(string(data)), opts.telegramChatID, nil, "", bktelegram.Options{
			ApproveText: "Approve", DenyText: "Deny", IgnoredAnswer: "Request decision ignored",
		})
		if err != nil {
			return nil, err
		}
	}
	var notifierService notify.Notifier
	var poller routes.DecisionPoller
	if notifier != nil {
		notifierService = notifier
		poller = notifier
	}
	server, err := routes.New(routes.Options{
		Policy: policy, Catalog: snapshot, Database: database,
		Identities: plan.SystemIdentityResolver{}, Helper: helper, ClientSecrets: clients, OperatorSecrets: operators,
		Notifier: notifierService, Poller: poller, Audit: audit.New(stderr), OperatorConfigured: len(operators) > 0,
	})
	if err != nil {
		_ = database.Close()
	}
	return server, err
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
