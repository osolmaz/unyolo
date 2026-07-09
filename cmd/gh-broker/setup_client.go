package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/osolmaz/brokerkit/clientconfig"
)

const setupUsage = `usage:
  gh-broker setup systemd --scope-file FILE (--dev-token-fallback --github-token-file FILE | --github-app-id-file FILE --github-app-private-key-file FILE --github-webhook-secret-file FILE) [flags]
  gh-broker setup client --client <name> --url <url> --secret-file <path> [--home-dir <path>]`

type setupClientOptions struct {
	ClientName string
	URL        string
	SecretFile string
	HomeDir    string
}

type setupSystemdOptions struct {
	User                    string
	Group                   string
	ConfigDir               string
	StateDir                string
	SystemdDir              string
	BinaryPath              string
	GitHubTokenFile         string
	GitHubAppIDFile         string
	GitHubAppPrivateKeyFile string
	GitHubWebhookSecretFile string
	ScopeFile               string
	ClientName              string
	SharedSecret            string
	SharedSecretFile        string
	SharedSecretStdin       bool
	BindAddr                string
	Port                    int
	DevTokenFallback        bool
	DryRun                  bool
	NoStart                 bool
	AllowNonRoot            bool
	CommandRunner           commandRunner
}

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run() // #nosec G204 -- setup commands and argv are fixed by gh-broker.
}

func runSetup(stdout io.Writer, stderr io.Writer, args []string) error {
	return runSetupWithContext(context.Background(), stdout, stderr, args)
}

func runSetupWithContext(ctx context.Context, stdout io.Writer, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return errors.New(setupUsage)
	}
	switch args[0] {
	case "client":
		return runSetupClientCommand(stdout, stderr, args[1:])
	case "systemd":
		return runSetupSystemdCommand(ctx, stdout, stderr, os.Stdin, args[1:])
	default:
		return errors.New(setupUsage)
	}
}

func runSetupClientCommand(stdout io.Writer, stderr io.Writer, args []string) error {
	opts, err := parseSetupClient(stderr, args)
	if err != nil {
		return err
	}
	return runSetupClient(stdout, opts)
}

func runSetupSystemdCommand(ctx context.Context, stdout io.Writer, stderr io.Writer, stdin io.Reader, args []string) error {
	opts, err := parseSetupSystemd(stderr, stdin, args)
	if err != nil {
		return err
	}
	opts.CommandRunner = osCommandRunner{}
	return runSetupSystemd(ctx, stdout, opts)
}

func parseSetupClient(stderr io.Writer, args []string) (setupClientOptions, error) {
	opts := setupClientOptions{ClientName: "bob"}
	fs, flagOutput := setupClientFlagSet(&opts)
	if err := fs.Parse(args); err != nil {
		return setupClientOptions{}, handleSetupClientFlagError(stderr, flagOutput.String(), err)
	}
	if fs.NArg() != 0 {
		return setupClientOptions{}, errors.New("setup client does not accept positional arguments")
	}
	if err := defaultSetupClientHome(&opts); err != nil {
		return setupClientOptions{}, err
	}
	return opts, validateSetupClientOptions(opts)
}

func setupClientFlagSet(opts *setupClientOptions) (*flag.FlagSet, *strings.Builder) {
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("gh-broker setup client", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name to read from the secrets file")
	fs.StringVar(&opts.URL, "url", "", "broker base URL")
	fs.StringVar(&opts.SecretFile, "secret-file", "", "file containing broker client secrets")
	fs.StringVar(&opts.HomeDir, "home-dir", "", "home directory that receives .config/gh-broker/client.env")
	return fs, &flagOutput
}

func handleSetupClientFlagError(stderr io.Writer, flagOutput string, err error) error {
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.Copy(stderr, strings.NewReader(flagOutput))
		return nil
	}
	return errors.New("invalid setup client flags")
}

func defaultSetupClientHome(opts *setupClientOptions) error {
	if opts.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("resolve home directory: %w", err)
		}
		opts.HomeDir = home
	}
	return nil
}

func validateSetupClientOptions(opts setupClientOptions) error {
	if opts.ClientName == "" {
		return errors.New("--client must not be empty")
	}
	if opts.URL == "" {
		return errors.New("--url is required")
	}
	if opts.SecretFile == "" {
		return errors.New("--secret-file is required")
	}
	if opts.HomeDir == "" {
		return errors.New("--home-dir must not be empty")
	}
	return nil
}

func runSetupClient(stdout io.Writer, opts setupClientOptions) error {
	secret, err := clientconfig.SecretFromFile(opts.SecretFile, opts.ClientName)
	if err != nil {
		return err
	}
	path, err := clientconfig.WriteForHomeOwner(clientconfig.Config{
		BrokerName: "gh-broker",
		EnvPrefix:  "GH_BROKER",
		URL:        opts.URL,
		Secret:     secret,
		HomeDir:    opts.HomeDir,
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "gh-broker client config written\n  client: %s\n  file: %s\n  url: %s\n", opts.ClientName, path, opts.URL)
	return err
}

func parseSetupSystemd(stderr io.Writer, stdin io.Reader, args []string) (setupSystemdOptions, error) {
	opts := setupSystemdOptions{
		User:          "gh-broker",
		Group:         "gh-broker",
		ConfigDir:     "/etc/gh-broker",
		StateDir:      "/var/lib/gh-broker",
		SystemdDir:    "/etc/systemd/system",
		ClientName:    "bob",
		BindAddr:      "127.0.0.1",
		Port:          8081,
		CommandRunner: osCommandRunner{},
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("gh-broker setup systemd", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.User, "user", opts.User, "system user for the broker service")
	fs.StringVar(&opts.Group, "group", opts.Group, "system group for the broker service")
	fs.StringVar(&opts.ConfigDir, "config-dir", opts.ConfigDir, "directory for broker config and secrets")
	fs.StringVar(&opts.StateDir, "state-dir", opts.StateDir, "directory for broker state")
	fs.StringVar(&opts.SystemdDir, "systemd-dir", opts.SystemdDir, "directory for the systemd unit")
	fs.StringVar(&opts.BinaryPath, "binary", "", "gh-broker binary path for the service")
	fs.StringVar(&opts.GitHubTokenFile, "github-token-file", "", "file containing a GitHub token for dev-token fallback")
	fs.StringVar(&opts.GitHubAppIDFile, "github-app-id-file", "", "file containing the GitHub App id")
	fs.StringVar(&opts.GitHubAppPrivateKeyFile, "github-app-private-key-file", "", "file containing the GitHub App private key")
	fs.StringVar(&opts.GitHubWebhookSecretFile, "github-webhook-secret-file", "", "file containing the GitHub webhook secret")
	fs.StringVar(&opts.ScopeFile, "scope-file", "", "policy scope JSON file")
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name written to the secrets file")
	fs.StringVar(&opts.SharedSecretFile, "shared-secret-file", "", "file containing the broker client secret")
	fs.BoolVar(&opts.SharedSecretStdin, "shared-secret-stdin", false, "read the broker client secret from stdin")
	fs.StringVar(&opts.BindAddr, "bind-addr", opts.BindAddr, "broker bind address")
	fs.IntVar(&opts.Port, "port", opts.Port, "broker port")
	fs.BoolVar(&opts.DevTokenFallback, "dev-token-fallback", false, "configure the current GitHub token fallback runtime")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "print planned actions without writing files or running systemctl")
	fs.BoolVar(&opts.NoStart, "no-start", false, "write files but do not enable or start the service")
	fs.BoolVar(&opts.AllowNonRoot, "allow-non-root", false, "allow setup to run without root; intended for tests")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(flagOutput.String()))
			return setupSystemdOptions{}, nil
		}
		return setupSystemdOptions{}, errors.New("invalid setup systemd flags")
	}
	if fs.NArg() != 0 {
		return setupSystemdOptions{}, errors.New("setup systemd does not accept positional arguments")
	}
	if opts.BinaryPath == "" {
		path, err := defaultBinaryPath()
		if err != nil {
			return setupSystemdOptions{}, fmt.Errorf("resolve executable path: %w", err)
		}
		opts.BinaryPath = path
	}
	secret, err := setupSharedSecret(opts, stdin)
	if err != nil {
		return setupSystemdOptions{}, err
	}
	opts.SharedSecret = secret
	return opts, validateSetupSystemdOptions(opts)
}

func setupSharedSecret(opts setupSystemdOptions, stdin io.Reader) (string, error) {
	switch {
	case opts.SharedSecretFile != "" && opts.SharedSecretStdin:
		return "", errors.New("--shared-secret-file and --shared-secret-stdin are mutually exclusive")
	case opts.SharedSecretFile != "":
		data, err := os.ReadFile(opts.SharedSecretFile) // #nosec G304 -- operator configured setup path.
		if err != nil {
			return "", fmt.Errorf("read --shared-secret-file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	case opts.SharedSecretStdin:
		data, err := io.ReadAll(io.LimitReader(stdin, 4096))
		if err != nil {
			return "", fmt.Errorf("read --shared-secret-stdin: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	default:
		return generateSharedSecret()
	}
}

func defaultBinaryPath() (string, error) {
	const globalPath = "/usr/local/bin/gh-broker"
	if info, err := os.Stat(globalPath); err == nil && !info.IsDir() {
		return globalPath, nil
	}
	return os.Executable()
}

func generateSharedSecret() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate shared secret: %w", err)
	}
	return hex.EncodeToString(data[:]), nil
}

func validateSetupSystemdOptions(opts setupSystemdOptions) error {
	if err := validateSetupSystemdCredentialOptions(opts); err != nil {
		return err
	}
	return validateSetupSystemdClientOptions(opts)
}

func validateSetupSystemdCredentialOptions(opts setupSystemdOptions) error {
	if opts.ScopeFile == "" {
		return errors.New("--scope-file is required")
	}
	if opts.DevTokenFallback {
		return validateDevTokenSetup(opts)
	}
	return validateGitHubAppSetup(opts)
}

func validateDevTokenSetup(opts setupSystemdOptions) error {
	if opts.GitHubTokenFile == "" {
		return errors.New("--github-token-file is required with --dev-token-fallback")
	}
	return nil
}

func validateGitHubAppSetup(opts setupSystemdOptions) error {
	if opts.GitHubAppIDFile == "" || opts.GitHubAppPrivateKeyFile == "" || opts.GitHubWebhookSecretFile == "" {
		return errors.New("GitHub App credential files are required unless --dev-token-fallback is set")
	}
	return nil
}

func validateSetupSystemdClientOptions(opts setupSystemdOptions) error {
	if opts.ClientName == "" {
		return errors.New("--client must not be empty")
	}
	if len([]byte(opts.SharedSecret)) < 32 {
		return errors.New("broker client secret must be at least 32 bytes")
	}
	if strings.Contains(opts.ClientName, "=") || strings.ContainsAny(opts.ClientName, "\r\n") {
		return errors.New("--client must not contain '=' or newlines")
	}
	if strings.ContainsAny(opts.SharedSecret, "\r\n") {
		return errors.New("broker client secret must not contain newlines")
	}
	if opts.Port <= 0 || opts.Port > 65535 {
		return errors.New("--port must be between 1 and 65535")
	}
	return nil
}
