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

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorserver"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/privexec"
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
	handled, err := privexec.RunInternalChild(args)
	if handled {
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "sudo-broker-exec:", err)
			return 126
		}
		return 0
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		_, _ = fmt.Fprintln(os.Stdout, version)
		return 0
	}
	opts, err := parseOptions(args)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sudo-broker-exec:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, opts); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "sudo-broker-exec:", err)
		return 1
	}
	return 0
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
	if err := hostcheck.ValidateRootFile(opts.catalogPath); err != nil {
		return fmt.Errorf("catalog is unsafe: %w", err)
	}
	if err := hostcheck.ValidateRootDirectory(filepath.Dir(opts.statePath)); err != nil {
		return fmt.Errorf("state directory is unsafe: %w", err)
	}
	identity, err := (plan.SystemIdentityResolver{}).Lookup(opts.brokerUser)
	if err != nil || identity.UID == 0 {
		return errors.New("broker user must be an existing non-root user")
	}
	if err := hostcheck.ValidateStaleSocket(opts.socketPath, identity.UID); err != nil {
		return fmt.Errorf("socket path is unsafe: %w", err)
	}
	if err := os.Remove(opts.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	snapshot, err := catalog.Load(opts.catalogPath)
	if err != nil {
		return err
	}
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}
	runner, err := privexec.NewRunner(selfPath, identity.UID)
	if err != nil {
		return err
	}
	server, err := executorserver.New(executorserver.Config{
		Catalog: snapshot, Identities: plan.SystemIdentityResolver{}, Runner: runner, StatePath: opts.statePath,
		ExpectedPeerUID: identity.UID, BrokerUID: identity.UID, PeerUID: executorserver.DefaultPeerUID,
	})
	if err != nil {
		return err
	}
	listener, err := listenUnix(opts.socketPath, identity.UID, identity.GID)
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close(); _ = os.Remove(opts.socketPath) }() // #nosec G703 -- socketPath is absolute, normalized, and validated before listener creation.
	return server.Serve(ctx, listener)
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
