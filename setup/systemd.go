package setup

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/internal/validatex"
)

// SystemdDefaults configures shared Linux service setup flags.
type SystemdDefaults struct {
	BrokerName string
	User       string
	Group      string
	ClientName string
	BindAddr   string
	Port       int
}

// SystemdOptions contains the broker-neutral service setup fields.
type SystemdOptions struct {
	BrokerName        string
	User              string
	Group             string
	ConfigDir         string
	StateDir          string
	SystemdDir        string
	BinaryPath        string
	ClientName        string
	SharedSecretFile  string
	SharedSecretStdin bool
	BindAddr          string
	Port              int
	DryRun            bool
	NoStart           bool
	AllowNonRoot      bool
}

// DefaultSystemdOptions returns the common broker-family Linux layout.
func DefaultSystemdOptions(defaults SystemdDefaults) SystemdOptions {
	return SystemdOptions{
		BrokerName: defaults.BrokerName,
		User:       defaults.User,
		Group:      defaults.Group,
		ConfigDir:  filepath.Join("/etc", defaults.BrokerName),
		StateDir:   filepath.Join("/var/lib", defaults.BrokerName),
		SystemdDir: "/etc/systemd/system",
		ClientName: defaults.ClientName,
		BindAddr:   defaults.BindAddr,
		Port:       defaults.Port,
	}
}

// BindSystemdFlags adds the shared setup systemd flags to fs.
func BindSystemdFlags(fs *flag.FlagSet, opts *SystemdOptions) {
	fs.StringVar(&opts.User, "user", opts.User, "system user for the broker service")
	fs.StringVar(&opts.Group, "group", opts.Group, "system group for the broker service")
	fs.StringVar(&opts.ConfigDir, "config-dir", opts.ConfigDir, "directory for broker config and secrets")
	fs.StringVar(&opts.StateDir, "state-dir", opts.StateDir, "directory for broker state")
	fs.StringVar(&opts.SystemdDir, "systemd-dir", opts.SystemdDir, "directory for the systemd unit")
	fs.StringVar(&opts.BinaryPath, "binary", opts.BinaryPath, "broker binary path for the service")
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name written to the secrets file")
	fs.StringVar(&opts.SharedSecretFile, "shared-secret-file", "", "file containing the broker client secret")
	fs.BoolVar(&opts.SharedSecretStdin, "shared-secret-stdin", false, "read the broker client secret from stdin")
	fs.StringVar(&opts.BindAddr, "bind-addr", opts.BindAddr, "broker bind address")
	fs.IntVar(&opts.Port, "port", opts.Port, "broker port")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "print planned actions without writing files or running systemctl")
	fs.BoolVar(&opts.NoStart, "no-start", false, "write files but do not enable or start the service")
	fs.BoolVar(&opts.AllowNonRoot, "allow-non-root", false, "allow setup without root; intended for tests")
}

// FinalizeSystemd resolves the current executable and validates opts.
func FinalizeSystemd(opts SystemdOptions) (SystemdOptions, error) {
	if opts.BinaryPath == "" {
		path, err := os.Executable()
		if err != nil {
			return SystemdOptions{}, fmt.Errorf("resolve executable path: %w", err)
		}
		opts.BinaryPath = path
	}
	if resolved, err := filepath.EvalSymlinks(opts.BinaryPath); err == nil {
		opts.BinaryPath = resolved
	}
	return opts, opts.Validate()
}

// Validate validates shared Linux service setup fields.
func (opts SystemdOptions) Validate() error {
	if strings.TrimSpace(opts.BrokerName) == "" {
		return errors.New("broker name is required")
	}
	if err := validatex.AccountNames(map[string]string{"user": opts.User, "group": opts.Group, "client": opts.ClientName}); err != nil {
		return err
	}
	if err := validatex.AbsolutePaths(map[string]string{"config-dir": opts.ConfigDir, "state-dir": opts.StateDir, "systemd-dir": opts.SystemdDir, "binary": opts.BinaryPath}, true); err != nil {
		return err
	}
	return validateListenAddress(opts.BindAddr, opts.Port)
}

func validateListenAddress(bindAddr string, port int) error {
	if ip := net.ParseIP(bindAddr); ip == nil && bindAddr != "localhost" {
		return errors.New("--bind-addr must be an IP address or localhost")
	}
	if port < 1 || port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	return nil
}

// ListenAddress returns bind address and port in net/http form.
func (opts SystemdOptions) ListenAddress() string {
	return net.JoinHostPort(opts.BindAddr, strconv.Itoa(opts.Port))
}
