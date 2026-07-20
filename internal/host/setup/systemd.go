package setup

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/internal/config/client"
	"github.com/osolmaz/brokerkit/internal/validatex"
	"github.com/osolmaz/brokerkit/transport/endpoint"
)

// SystemdDefaults configures shared Linux service setup flags.
type SystemdDefaults struct {
	BrokerName string
	User       string
	Group      string
	ClientName string
	Endpoint   string
}

// SystemdOptions contains the broker-neutral service setup fields.
type SystemdOptions struct {
	BrokerName          string
	User                string
	Group               string
	ConfigDir           string
	StateDir            string
	SystemdDir          string
	BinaryPath          string
	ClientName          string
	AgentUser           string
	OperatorUser        string
	AgentAccessGroup    string
	OperatorAccessGroup string
	SharedSecretFile    string
	SharedSecretStdin   bool
	Endpoint            string
	DryRun              bool
	NoStart             bool
	AllowNonRoot        bool
}

// DefaultSystemdOptions returns the common broker-family Linux layout.
func DefaultSystemdOptions(defaults SystemdDefaults) SystemdOptions {
	return SystemdOptions{
		BrokerName:          defaults.BrokerName,
		User:                defaults.User,
		Group:               defaults.Group,
		ConfigDir:           filepath.Join("/etc", defaults.BrokerName),
		StateDir:            filepath.Join("/var/lib", defaults.BrokerName),
		SystemdDir:          "/etc/systemd/system",
		ClientName:          defaults.ClientName,
		Endpoint:            defaults.Endpoint,
		AgentAccessGroup:    defaults.BrokerName + "-agent",
		OperatorAccessGroup: defaults.BrokerName + "-operator",
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
	fs.StringVar(&opts.AgentUser, "agent-user", opts.AgentUser, "local Unix user granted access to the agent socket")
	fs.StringVar(&opts.OperatorUser, "operator-user", opts.OperatorUser, "local Unix user granted access to the operator socket")
	fs.StringVar(&opts.AgentAccessGroup, "agent-access-group", opts.AgentAccessGroup, "system group allowed to connect to the agent socket")
	fs.StringVar(&opts.OperatorAccessGroup, "operator-access-group", opts.OperatorAccessGroup, "system group allowed to connect to the operator socket")
	fs.StringVar(&opts.SharedSecretFile, "shared-secret-file", "", "file containing the broker client secret")
	fs.BoolVar(&opts.SharedSecretStdin, "shared-secret-stdin", false, "read the broker client secret from stdin")
	fs.StringVar(&opts.Endpoint, "endpoint", opts.Endpoint, "broker agent endpoint URI")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "print planned actions without writing files or running systemctl")
	fs.BoolVar(&opts.NoStart, "no-start", false, "write files but do not enable or start the service")
	fs.BoolVar(&opts.AllowNonRoot, "allow-non-root", false, "allow setup without root; intended for tests")
}

// FinalizeSystemd resolves the current executable and validates opts.
func FinalizeSystemd(opts SystemdOptions) (SystemdOptions, error) {
	resolved, err := resolveExecutablePath(opts.BinaryPath)
	if err != nil {
		return SystemdOptions{}, err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return SystemdOptions{}, fmt.Errorf("stat executable path: %w", err)
	}
	if err := validateExecutableInfo(info); err != nil {
		return SystemdOptions{}, err
	}
	if requiresTrustedExecutable(opts) {
		if err := validateTrustedExecutable(resolved); err != nil {
			return SystemdOptions{}, err
		}
	}
	opts.BinaryPath = resolved
	return opts, opts.Validate()
}

func requiresTrustedExecutable(opts SystemdOptions) bool {
	return os.Geteuid() == 0
}

func validateTrustedExecutable(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), current), current) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect executable path: %w", err)
		}
		if err := validateTrustedPathComponent(current, info); err != nil {
			return err
		}
	}
	return nil
}

func validateTrustedPathComponent(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("executable path ownership is unavailable for %s", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("executable path component must be root-owned: %s", path)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("executable path component must not be mutable by non-root users: %s", path)
	}
	return nil
}

func resolveExecutablePath(path string) (string, error) {
	if path == "" {
		resolved, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve executable path: %w", err)
		}
		path = resolved
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return resolved, nil
}

func validateExecutableInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("executable path must be a regular executable file")
	}
	return nil
}

// Validate validates shared Linux service setup fields.
func (opts SystemdOptions) Validate() error {
	if strings.TrimSpace(opts.BrokerName) == "" {
		return errors.New("broker name is required")
	}
	if err := validateSystemdAccounts(opts); err != nil {
		return err
	}
	if opts.AgentAccessGroup == opts.OperatorAccessGroup {
		return errors.New("agent and operator access groups must differ")
	}
	if err := clientconfig.ValidateClientName(opts.ClientName); err != nil {
		return err
	}
	if err := validatex.AbsolutePaths(map[string]string{"config-dir": opts.ConfigDir, "state-dir": opts.StateDir, "systemd-dir": opts.SystemdDir, "binary": opts.BinaryPath}, true); err != nil {
		return err
	}
	parsed, err := endpoint.Parse(opts.Endpoint, endpoint.ParseOptions{})
	if err != nil {
		return fmt.Errorf("--endpoint: %w", err)
	}
	if parsed.Scheme() == endpoint.SchemeFD {
		return errors.New("--endpoint cannot use a raw inherited descriptor")
	}
	return nil
}

func validateSystemdAccounts(opts SystemdOptions) error {
	return validatex.AccountNames(map[string]string{
		"user": opts.User, "group": opts.Group, "agent user": opts.AgentUser,
		"operator user": opts.OperatorUser, "agent access group": opts.AgentAccessGroup,
		"operator access group": opts.OperatorAccessGroup,
	})
}
