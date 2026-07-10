package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const setupUsage = `usage:
  hf-broker setup systemd --hf-token-file <path> --repo <owner/name> --repo-type <model|dataset|space> [flags]
  hf-broker setup client --client <name> --url <url> --secret-file <path> [--home-dir <path>]`

var hubNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type setupSystemdOptions struct {
	bksetup.SystemdOptions
	HFTokenFile   string
	Repo          string
	RepoType      string
	SharedSecret  string
	CommandRunner bkservice.CommandRunner
}

func runSetup(ctx context.Context, stdout, stderr io.Writer, args []string) error {
	return runSetupInput(ctx, os.Stdin, stdout, stderr, args)
}

func runSetupInput(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return exitError{code: 64, message: setupUsage}
	}
	switch args[0] {
	case "systemd":
		opts, err := parseSetupSystemdInput(stderr, stdin, args[1:])
		if err != nil {
			return err
		}
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
	return parseSetupSystemdInput(stderr, strings.NewReader(""), args)
}

func parseSetupSystemdInput(stderr io.Writer, stdin io.Reader, args []string) (setupSystemdOptions, error) {
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.DefaultSystemdOptions(bksetup.SystemdDefaults{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080,
		}),
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("hf-broker setup systemd", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	bksetup.BindSystemdFlags(fs, &opts.SystemdOptions)
	fs.StringVar(&opts.HFTokenFile, "hf-token-file", "", "file containing the upstream Hugging Face token")
	fs.StringVar(&opts.Repo, "repo", "", "allowed Hub repo as owner/name")
	fs.StringVar(&opts.RepoType, "repo-type", "", "Hub repo type: model, dataset, or space")
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
	finalized, err := bksetup.FinalizeSystemd(opts.SystemdOptions)
	if err != nil {
		return setupSystemdOptions{}, exitError{code: 64, message: err.Error()}
	}
	opts.SystemdOptions = finalized
	secret, err := bksetup.ResolveSecret(bksetup.SecretInput{
		File: opts.SharedSecretFile, Stdin: opts.SharedSecretStdin,
	}, stdin)
	if err != nil {
		return setupSystemdOptions{}, exitError{code: 64, message: err.Error()}
	}
	opts.SharedSecret = secret
	return opts, validateSetupSystemdOptions(opts)
}

func validateSetupSystemdOptions(opts setupSystemdOptions) error {
	if err := opts.Validate(); err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if err := validateSetupRequired(opts); err != nil {
		return err
	}
	if err := validateSetupRepo(opts); err != nil {
		return err
	}
	return nil
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
	return brokerBaseURL(bindAddr, port) + repoRemotePath(repoType, repo)
}

func brokerBaseURL(bindAddr string, port int) string {
	host := bindAddr
	if host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}
