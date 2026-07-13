package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorclient"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/routes"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/notify"
	bktelegram "github.com/osolmaz/brokerkit/notify/telegram"
	corepolicy "github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/secretfile"
	"github.com/osolmaz/brokerkit/state"
)

type serveOptions struct {
	policyPath      string
	catalogPath     string
	secretsPath     string
	operatorSecrets string
	stateDirectory  string
	helperSocket    string
	bindAddress     string
	operatorAddress string
	telegramToken   string
	telegramChatID  int64
}

func runServe(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	return runServeWith(ctx, args, stdout, stderr, os.Geteuid, buildServer, serveHTTP)
}

func runServeWith(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, geteuid func() int,
	build func(serveOptions, io.Writer) (*routes.Server, error), serve func(context.Context, []*http.Server) error) error {
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
	servers := []*http.Server{httpServer(opts.bindAddress, server.Handler(), false)}
	if server.OperatorHandler() != nil {
		servers = append(servers, httpServer(opts.operatorAddress, server.OperatorHandler(), true))
	}
	for _, value := range servers {
		_, _ = fmt.Fprintf(stdout, "sudo-broker listening on http://%s\n", value.Addr)
	}
	return serve(ctx, servers)
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
	flags.StringVar(&opts.bindAddress, "bind", "127.0.0.1:8084", "agent listener")
	flags.StringVar(&opts.operatorAddress, "operator-bind", "127.0.0.1:8085", "operator listener")
	flags.StringVar(&opts.telegramToken, "telegram-token-file", "", "private Telegram bot token file")
	flags.Int64Var(&opts.telegramChatID, "telegram-chat-id", 0, "Telegram approval chat id")
	if err := flags.Parse(args); err != nil {
		return serveOptions{}, err
	}
	if flags.NArg() != 0 || opts.policyPath == "" || opts.catalogPath == "" || opts.secretsPath == "" || opts.stateDirectory == "" || opts.helperSocket == "" {
		return serveOptions{}, errors.New("--policy, --catalog, --secrets, --state, and --helper-socket are required")
	}
	if err := validateLoopbackAddress(opts.bindAddress); err != nil {
		return serveOptions{}, fmt.Errorf("agent listener: %w", err)
	}
	if opts.operatorSecrets != "" {
		if err := validateLoopbackAddress(opts.operatorAddress); err != nil {
			return serveOptions{}, fmt.Errorf("operator listener: %w", err)
		}
		if opts.operatorAddress == opts.bindAddress {
			return serveOptions{}, errors.New("agent and operator listeners must differ")
		}
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

func httpServer(address string, handler http.Handler, operator bool) *http.Server {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 35 * time.Second, IdleTimeout: 60 * time.Second}
	if operator {
		server.WriteTimeout = 0
	}
	return server
}

func serveHTTP(ctx context.Context, servers []*http.Server) error {
	errorsChannel := make(chan error, len(servers))
	for _, server := range servers {
		go func(value *http.Server) { errorsChannel <- value.ListenAndServe() }(server)
	}
	select {
	case err := <-errorsChannel:
		_ = shutdownHTTP(servers)
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		return shutdownHTTP(servers)
	}
}

func shutdownHTTP(servers []*http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var values []error
	for _, server := range servers {
		values = append(values, server.Shutdown(ctx))
	}
	return errors.Join(values...)
}

func validateLoopbackAddress(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return errors.New("address must be host:port")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return errors.New("port is invalid")
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("address must be loopback-only")
	}
	return nil
}
