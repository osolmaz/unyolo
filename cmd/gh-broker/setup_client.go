package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const setupUsage = `usage:
  gh-broker setup systemd --scope-file FILE (--dev-token-fallback --github-token-file FILE | --github-app-id-file FILE --github-app-private-key-file FILE --github-webhook-secret-file FILE) [flags]
  gh-broker setup client --client <name> --url <url> --secret-file <path> [--home-dir <path>]`

type setupClientOptions = bksetup.ClientOptions

type setupSystemdOptions struct {
	bksetup.SystemdOptions
	GitHubTokenFile         string
	GitHubAppIDFile         string
	GitHubAppPrivateKeyFile string
	GitHubWebhookSecretFile string
	ScopeFile               string
	SharedSecret            string
	DevTokenFallback        bool
	CommandRunner           bkservice.CommandRunner
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
	opts, help, err := bksetup.ParseClient(stderr, args, ghClientDefaults())
	if err != nil {
		return err
	}
	if help {
		return nil
	}
	return runSetupClient(stdout, opts)
}

func runSetupSystemdCommand(ctx context.Context, stdout io.Writer, stderr io.Writer, stdin io.Reader, args []string) error {
	opts, help, err := parseSetupSystemdCommand(stderr, stdin, args)
	if err != nil {
		return err
	}
	return runParsedSystemdSetup(ctx, stdout, opts, help)
}

func runParsedSystemdSetup(ctx context.Context, stdout io.Writer, opts setupSystemdOptions, help bool) error {
	if help {
		return nil
	}
	return runSetupSystemd(ctx, stdout, opts)
}

func parseSetupClient(stderr io.Writer, args []string) (setupClientOptions, error) {
	opts, _, err := bksetup.ParseClient(stderr, args, ghClientDefaults())
	return opts, err
}

func ghClientDefaults() bksetup.ClientDefaults {
	return bksetup.ClientDefaults{BrokerName: "gh-broker", EnvPrefix: "GH_BROKER", ClientName: "bob"}
}

func validateSetupClientOptions(opts setupClientOptions) error {
	return opts.Validate()
}

func runSetupClient(stdout io.Writer, opts setupClientOptions) error {
	_, err := bksetup.ConfigureClient(stdout, opts)
	return err
}

func parseSetupSystemd(stderr io.Writer, stdin io.Reader, args []string) (setupSystemdOptions, error) {
	opts, _, err := parseSetupSystemdCommand(stderr, stdin, args)
	return opts, err
}

func parseSetupSystemdCommand(stderr io.Writer, stdin io.Reader, args []string) (setupSystemdOptions, bool, error) {
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.DefaultSystemdOptions(bksetup.SystemdDefaults{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ClientName: "bob", BindAddr: "127.0.0.1", Port: 8081,
		}),
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("gh-broker setup systemd", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	bksetup.BindSystemdFlags(fs, &opts.SystemdOptions)
	fs.StringVar(&opts.GitHubTokenFile, "github-token-file", "", "file containing a GitHub token for dev-token fallback")
	fs.StringVar(&opts.GitHubAppIDFile, "github-app-id-file", "", "file containing the GitHub App id")
	fs.StringVar(&opts.GitHubAppPrivateKeyFile, "github-app-private-key-file", "", "file containing the GitHub App private key")
	fs.StringVar(&opts.GitHubWebhookSecretFile, "github-webhook-secret-file", "", "file containing the GitHub webhook secret")
	fs.StringVar(&opts.ScopeFile, "scope-file", "", "policy scope JSON file")
	fs.BoolVar(&opts.DevTokenFallback, "dev-token-fallback", false, "configure the current GitHub token fallback runtime")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(flagOutput.String()))
			return setupSystemdOptions{}, true, nil
		}
		return setupSystemdOptions{}, false, errors.New("invalid setup systemd flags")
	}
	if fs.NArg() != 0 {
		return setupSystemdOptions{}, false, errors.New("setup systemd does not accept positional arguments")
	}
	finalized, err := bksetup.FinalizeSystemd(opts.SystemdOptions)
	if err != nil {
		return setupSystemdOptions{}, false, err
	}
	opts.SystemdOptions = finalized
	secret, err := bksetup.ResolveSecret(bksetup.SecretInput{File: opts.SharedSecretFile, Stdin: opts.SharedSecretStdin}, stdin)
	if err != nil {
		return setupSystemdOptions{}, false, err
	}
	opts.SharedSecret = secret
	return opts, false, validateSetupSystemdOptions(opts)
}

func validateSetupSystemdOptions(opts setupSystemdOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}
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
	_, err := bksetup.ResolveSecret(bksetup.SecretInput{Stdin: true}, strings.NewReader(opts.SharedSecret))
	return err
}
