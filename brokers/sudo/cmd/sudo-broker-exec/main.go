package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/catalog"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorserver"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/privexec"
)

var version = "dev"

type options struct {
	catalogPath string
	statePath   string
	socketPath  string
	brokerUser  string
}

func main() { os.Exit(mainCode(os.Args[1:])) }

func mainCode(args []string) int {
	if code, handled := handleInternalChild(args); handled {
		return code
	}
	if printVersion(args) {
		return 0
	}
	opts, err := parseOptions(args)
	if err != nil {
		return reportExecError(err, 2)
	}
	return runMain(opts)
}

func handleInternalChild(args []string) (int, bool) {
	handled, err := privexec.RunInternalChild(args)
	if !handled {
		return 0, false
	}
	if err != nil {
		return reportExecError(err, 126), true
	}
	return 0, true
}

func printVersion(args []string) bool {
	if len(args) != 1 || (args[0] != "--version" && args[0] != "version") {
		return false
	}
	_, _ = fmt.Fprintln(os.Stdout, version)
	return true
}

func runMain(opts options) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, opts); err != nil {
		return reportExecError(err, 1)
	}
	return 0
}

func reportExecError(err error, code int) int {
	_, _ = fmt.Fprintln(os.Stderr, "sudo-broker-exec:", err)
	return code
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("sudo-broker-exec", flag.ContinueOnError)
	flags.StringVar(&opts.catalogPath, "catalog", "", "root-owned command catalog")
	flags.StringVar(&opts.statePath, "state", "", "root-owned execution state")
	flags.StringVar(&opts.socketPath, "socket", "", "local helper Unix socket")
	flags.StringVar(&opts.brokerUser, "broker-user", "", "dedicated frontend user")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 || opts.catalogPath == "" || opts.statePath == "" || opts.socketPath == "" || opts.brokerUser == "" {
		return options{}, errors.New("--catalog, --state, --socket, and --broker-user are required")
	}
	return opts, nil
}

func run(ctx context.Context, opts options) error {
	if os.Geteuid() != 0 {
		return errors.New("helper must run as root")
	}
	server, listener, err := runtimeServerAndListener(opts)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(opts.socketPath) }() // #nosec G703 -- socketPath is absolute, normalized, and validated before listener creation.
	return server.Serve(ctx, listener)
}

func runtimeServerAndListener(opts options) (*executorserver.Server, *net.UnixListener, error) {
	setup, err := validateRuntime(opts)
	if err != nil {
		return nil, nil, err
	}
	return buildRuntimeServerAndListener(opts, setup.identity)
}

type runtimeSetup struct {
	identity plan.Identity
}

func validateRuntime(opts options) (runtimeSetup, error) {
	if err := validateStaticInputs(opts); err != nil {
		return runtimeSetup{}, err
	}
	return validateRuntimeIdentityAndSocket(opts)
}

func validateRuntimeIdentityAndSocket(opts options) (runtimeSetup, error) {
	identity, err := lookupBrokerIdentity(opts.brokerUser)
	if err != nil {
		return runtimeSetup{}, err
	}
	return runtimeSetup{identity: identity}, validateSocketPath(opts.socketPath, identity.UID)
}

func validateStaticInputs(opts options) error {
	if err := hostcheck.ValidateRootFile(opts.catalogPath); err != nil {
		return fmt.Errorf("catalog is unsafe: %w", err)
	}
	if err := hostcheck.ValidateRootDirectory(filepath.Dir(opts.statePath)); err != nil {
		return fmt.Errorf("state directory is unsafe: %w", err)
	}
	return nil
}

func lookupBrokerIdentity(name string) (plan.Identity, error) {
	identity, err := (plan.SystemIdentityResolver{}).Lookup(name)
	if err != nil || identity.UID == 0 {
		return plan.Identity{}, errors.New("broker user must be an existing non-root user")
	}
	return identity, nil
}

func validateSocketPath(path string, brokerUID uint32) error {
	if err := hostcheck.ValidateStaleSocket(path, brokerUID); err != nil {
		return fmt.Errorf("socket path is unsafe: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func newExecutorServer(opts options, identity plan.Identity) (*executorserver.Server, error) {
	snapshot, err := catalog.Load(opts.catalogPath)
	if err != nil {
		return nil, err
	}
	runner, err := newPrivilegedRunner(identity.UID)
	if err != nil {
		return nil, err
	}
	return executorserver.New(executorserver.Config{
		Catalog: snapshot, Identities: plan.SystemIdentityResolver{}, Runner: runner, StatePath: opts.statePath,
		ExpectedPeerUID: identity.UID, BrokerUID: identity.UID, PeerUID: executorserver.DefaultPeerUID,
	})
}

func buildRuntimeServerAndListener(opts options, identity plan.Identity) (*executorserver.Server, *net.UnixListener, error) {
	server, err := newExecutorServer(opts, identity)
	if err != nil {
		return nil, nil, err
	}
	listener, err := listenUnix(opts.socketPath, identity.UID, identity.GID)
	if err != nil {
		return nil, nil, err
	}
	return server, listener, nil
}

func newPrivilegedRunner(brokerUID uint32) (*privexec.Runner, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return privexec.NewRunner(selfPath, brokerUID)
}

func listenUnix(path string, uid uint32, gid uint32) (*net.UnixListener, error) {
	previousUmask := syscall.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(previousUmask)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, int(uid), int(gid)); err != nil { // #nosec G115 -- uid/gid are validated uint32 host identities.
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return listener, nil
}
