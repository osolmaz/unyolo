package setup

import (
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/osolmaz/brokerkit/internal/config/client"
	"github.com/osolmaz/brokerkit/internal/validatex"
	"github.com/osolmaz/brokerkit/transport/endpoint"
)

// SystemdDefaults configures shared Linux service setup flags.
type SystemdDefaults struct {
	BrokerName         string
	User               string
	Group              string
	ClientName         string
	Endpoint           string
	ManagedDestination string
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
	ManagedDestination  string
}

// DefaultSystemdOptions returns the common broker-family Linux layout.
func DefaultSystemdOptions(defaults SystemdDefaults) SystemdOptions {
	options := SystemdOptions{
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
		ManagedDestination:  defaults.ManagedDestination,
	}
	if options.ManagedDestination == "" {
		options.ManagedDestination = filepath.Join("bin", defaults.BrokerName)
	}
	return options
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
	resolved, managed, err := ResolveServiceExecutable(opts.BinaryPath, opts.ManagedDestination, opts.AllowNonRoot)
	if err != nil {
		return SystemdOptions{}, err
	}
	if err := validateFinalizedExecutable(opts, resolved, managed); err != nil {
		return SystemdOptions{}, err
	}
	opts.BinaryPath = resolved
	return opts, opts.Validate()
}

func validateFinalizedExecutable(opts SystemdOptions, resolved string, managed bool) error {
	if requiresManagedExecutable(opts) && !managed {
		return errors.New("production services must use the BrokerKit managed current release path")
	}
	if managed && !opts.NoStart {
		if _, err := filepath.EvalSymlinks(resolved); err != nil {
			return errors.New("managed executable must exist before service activation; use --no-start for initial bundle setup")
		}
	}
	return nil
}

// Validate validates shared Linux service setup fields.
func (opts SystemdOptions) Validate() error {
	checks := []func() error{
		opts.validateIdentity,
		func() error {
			return validatex.AbsolutePaths(map[string]string{"config-dir": opts.ConfigDir, "state-dir": opts.StateDir, "systemd-dir": opts.SystemdDir, "binary": opts.BinaryPath}, true)
		},
		opts.validateDestination,
		opts.validateEndpoint,
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func (opts SystemdOptions) validateIdentity() error {
	if strings.TrimSpace(opts.BrokerName) == "" {
		return errors.New("broker name is required")
	}
	if err := validateSystemdAccounts(opts); err != nil {
		return err
	}
	if opts.AgentAccessGroup == opts.OperatorAccessGroup {
		return errors.New("agent and operator access groups must differ")
	}
	return clientconfig.ValidateClientName(opts.ClientName)
}

func (opts SystemdOptions) validateDestination() error {
	if !safeManagedDestination(opts.ManagedDestination) {
		return errors.New("managed executable destination is invalid")
	}
	return nil
}

func (opts SystemdOptions) validateEndpoint() error {
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
