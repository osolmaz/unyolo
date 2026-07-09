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
	"regexp"
	"strconv"
	"strings"
)

const setupUsage = `usage:
  hf-broker setup systemd --hf-token-file <path> --repo <owner/name> --repo-type <model|dataset|space> [flags]
  hf-broker setup client --client <name> --url <url> --secret-file <path> [--home-dir <path>]`

var hubNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type setupSystemdOptions struct {
	User          string
	Group         string
	ConfigDir     string
	StateDir      string
	SystemdDir    string
	BinaryPath    string
	HFTokenFile   string
	Repo          string
	RepoType      string
	ClientName    string
	SharedSecret  string
	BindAddr      string
	Port          int
	DryRun        bool
	NoStart       bool
	AllowNonRoot  bool
	CommandRunner commandRunner
}

type commandRunner interface {
	Run(ctx context.Context, name string, args ...string) error
}

type osCommandRunner struct{}

func runSetup(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: setupUsage}
	}
	switch args[0] {
	case "systemd":
		opts, err := parseSetupSystemd(stderr, args[1:])
		if err != nil {
			return err
		}
		opts.CommandRunner = osCommandRunner{}
		return runSetupSystemd(ctx, stdout, opts)
	case "client":
		opts, err := parseSetupClient(stderr, args[1:])
		if err != nil {
			return err
		}
		return runSetupClient(stdout, opts)
	default:
		return exitError{code: 64, message: setupUsage}
	}
}

func parseSetupSystemd(stderr io.Writer, args []string) (setupSystemdOptions, error) {
	opts := setupSystemdOptions{
		User:          "hf-broker",
		Group:         "hf-broker",
		ConfigDir:     "/etc/hf-broker",
		StateDir:      "/var/lib/hf-broker",
		SystemdDir:    "/etc/systemd/system",
		ClientName:    "agent",
		BindAddr:      "127.0.0.1",
		Port:          8080,
		CommandRunner: osCommandRunner{},
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("hf-broker setup systemd", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	fs.StringVar(&opts.User, "user", opts.User, "system user for the broker service")
	fs.StringVar(&opts.Group, "group", opts.Group, "system group for the broker service")
	fs.StringVar(&opts.ConfigDir, "config-dir", opts.ConfigDir, "directory for broker config and secrets")
	fs.StringVar(&opts.StateDir, "state-dir", opts.StateDir, "directory for broker state")
	fs.StringVar(&opts.SystemdDir, "systemd-dir", opts.SystemdDir, "directory for the systemd unit")
	fs.StringVar(&opts.BinaryPath, "binary", "", "hf-broker binary path for the service")
	fs.StringVar(&opts.HFTokenFile, "hf-token-file", "", "file containing the upstream Hugging Face token")
	fs.StringVar(&opts.Repo, "repo", "", "allowed Hub repo as owner/name")
	fs.StringVar(&opts.RepoType, "repo-type", "", "Hub repo type: model, dataset, or space")
	fs.StringVar(&opts.ClientName, "client", opts.ClientName, "broker client name written to the secrets file")
	fs.StringVar(&opts.SharedSecret, "shared-secret", "", "broker client secret; generated when omitted")
	fs.StringVar(&opts.BindAddr, "bind-addr", opts.BindAddr, "broker bind address")
	fs.IntVar(&opts.Port, "port", opts.Port, "broker port")
	fs.BoolVar(&opts.DryRun, "dry-run", false, "print planned actions without writing files or running systemctl")
	fs.BoolVar(&opts.NoStart, "no-start", false, "write files but do not enable or start the service")
	fs.BoolVar(&opts.AllowNonRoot, "allow-non-root", false, "allow setup to run without root; intended for tests")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(flagOutput.String()))
			return setupSystemdOptions{}, exitError{code: 0}
		}
		return setupSystemdOptions{}, exitError{code: 64, message: "invalid setup systemd flags"}
	}
	if fs.NArg() != 0 {
		return setupSystemdOptions{}, exitError{code: 64, message: "setup systemd does not accept positional arguments"}
	}
	if opts.BinaryPath == "" {
		path, err := defaultBinaryPath()
		if err != nil {
			return setupSystemdOptions{}, fmt.Errorf("resolve executable path: %w", err)
		}
		opts.BinaryPath = path
	}
	if opts.SharedSecret == "" {
		secret, err := generateSharedSecret()
		if err != nil {
			return setupSystemdOptions{}, err
		}
		opts.SharedSecret = secret
	}
	return opts, validateSetupSystemdOptions(opts)
}

func defaultBinaryPath() (string, error) {
	const globalPath = "/usr/local/bin/hf-broker"
	if info, err := os.Stat(globalPath); err == nil && !info.IsDir() {
		return globalPath, nil
	}
	return os.Executable()
}

func validateSetupSystemdOptions(opts setupSystemdOptions) error {
	if err := validateSetupRequired(opts); err != nil {
		return err
	}
	if err := validateSetupRepo(opts); err != nil {
		return err
	}
	return validateSetupClient(opts)
}

func validateSetupRequired(opts setupSystemdOptions) error {
	if opts.HFTokenFile == "" {
		return exitError{code: 64, message: "--hf-token-file is required"}
	}
	if opts.Repo == "" {
		return exitError{code: 64, message: "--repo is required"}
	}
	if opts.RepoType == "" {
		return exitError{code: 64, message: "--repo-type is required"}
	}
	return nil
}

func validateSetupRepo(opts setupSystemdOptions) error {
	if !validRepo(opts.Repo) {
		return exitError{code: 64, message: "--repo must be owner/name"}
	}
	if !validRepoType(opts.RepoType) {
		return exitError{code: 64, message: "--repo-type must be model, dataset, or space"}
	}
	if opts.Port <= 0 || opts.Port > 65535 {
		return exitError{code: 64, message: "--port must be between 1 and 65535"}
	}
	return nil
}

func validateSetupClient(opts setupSystemdOptions) error {
	if opts.ClientName == "" {
		return exitError{code: 64, message: "--client must not be empty"}
	}
	if len(opts.SharedSecret) < 32 {
		return exitError{code: 64, message: "--shared-secret must be at least 32 bytes"}
	}
	if strings.Contains(opts.ClientName, "=") || strings.ContainsAny(opts.ClientName, "\r\n") {
		return exitError{code: 64, message: "--client must not contain '=' or newlines"}
	}
	if strings.ContainsAny(opts.SharedSecret, "\r\n") {
		return exitError{code: 64, message: "--shared-secret must not contain newlines"}
	}
	return nil
}

func validRepo(repo string) bool {
	parts := strings.Split(repo, "/")
	return len(parts) == 2 && validHubName(parts[0]) && validHubName(parts[1])
}

func validHubName(name string) bool {
	return hubNamePattern.MatchString(name)
}

func validRepoType(repoType string) bool {
	return repoType == "model" || repoType == "dataset" || repoType == "space"
}

func generateSharedSecret() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", fmt.Errorf("generate shared secret: %w", err)
	}
	return hex.EncodeToString(data[:]), nil
}

func repoRemotePath(repoType, repo string) string {
	switch repoType {
	case "dataset":
		return "/datasets/" + repo
	case "space":
		return "/spaces/" + repo
	default:
		return "/" + repo
	}
}

func brokerURL(bindAddr string, port int, repoType, repo string) string {
	host := bindAddr
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + host + ":" + strconv.Itoa(port) + repoRemotePath(repoType, repo)
}
