package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/policypreset"
	"github.com/osolmaz/brokerkit/clientconfig"
	"github.com/osolmaz/brokerkit/endpoint"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const setupUsage = `usage:
  gh-broker setup systemd [--policy-preset request-all-agent-operations | --scope-file FILE] (--dev-token-fallback --github-token-file FILE | --github-app-id-file FILE --github-app-private-key-file FILE --github-webhook-secret-file FILE) [flags]
  gh-broker setup launchd [--policy-preset request-all-agent-operations | --scope-file FILE] (--dev-token-fallback --github-token-file FILE | --github-app-id-file FILE --github-app-private-key-file FILE --github-webhook-secret-file FILE) [flags]
  gh-broker setup github-user enroll|rotate --state-dir DIR --credential-file FILE --github-app-client-id-file FILE --github-app-client-secret-file FILE
  gh-broker setup github-user revoke --state-dir DIR --user-id ID --github-app-client-id-file FILE --github-app-client-secret-file FILE
  gh-broker setup client --client <name> --endpoint <uri> --secret-file <path> [--home-dir <path>]`

type setupClientOptions = bksetup.ClientOptions

type setupSystemdOptions struct {
	bksetup.SystemdOptions
	GitHubTokenFile           string
	GitHubAppIDFile           string
	GitHubAppPrivateKeyFile   string
	GitHubAppClientIDFile     string
	GitHubAppClientSecretFile string
	GitHubUserID              int64
	GitHubWebhookSecretFile   string
	ScopeFile                 string
	PolicyPreset              string
	DeniedOperations          bksetup.StringListFlag
	ResetDeniedOperations     bool
	ReplacePolicy             bool
	PolicyPresetExplicit      bool
	SharedSecret              string
	OperatorID                string
	OperatorSecretFile        string
	OperatorSecret            string
	OperatorEndpoint          string
	TelegramBotTokenFile      string
	TelegramChatID            int64
	DevTokenFallback          bool
	CommandRunner             bkservice.CommandRunner
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
	case "launchd":
		return runSetupLaunchdCommand(ctx, stdout, stderr, os.Stdin, args[1:])
	case "github-user":
		return runSetupGitHubUser(ctx, stdout, stderr, args[1:])
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
	return bksetup.ClientDefaults{BrokerName: "gh-broker", EnvPrefix: "GH_BROKER"}
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
			Endpoint: "unix:///run/brokerkit/github/agent/broker.sock",
		}),
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("gh-broker setup systemd", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	bksetup.BindSystemdFlags(fs, &opts.SystemdOptions)
	fs.StringVar(&opts.GitHubTokenFile, "github-token-file", "", "file containing a GitHub token for dev-token fallback")
	fs.StringVar(&opts.GitHubAppIDFile, "github-app-id-file", "", "file containing the GitHub App id")
	fs.StringVar(&opts.GitHubAppPrivateKeyFile, "github-app-private-key-file", "", "file containing the GitHub App private key")
	fs.StringVar(&opts.GitHubAppClientIDFile, "github-app-client-id-file", "", "file containing the GitHub App OAuth client id for user credentials")
	fs.StringVar(&opts.GitHubAppClientSecretFile, "github-app-client-secret-file", "", "file containing the GitHub App OAuth client secret for user credentials")
	fs.Int64Var(&opts.GitHubUserID, "github-user-id", 0, "immutable GitHub user id for user credential operations")
	fs.StringVar(&opts.GitHubWebhookSecretFile, "github-webhook-secret-file", "", "file containing the GitHub webhook secret")
	fs.StringVar(&opts.ScopeFile, "scope-file", "", "policy scope JSON file")
	fs.StringVar(&opts.PolicyPreset, "policy-preset", policypreset.RequestAllAgentOperations, "provider-owned policy preset")
	fs.Var(&opts.DeniedOperations, "deny-operation", "exact operation to deny in the preset; repeatable")
	fs.BoolVar(&opts.ResetDeniedOperations, "reset-denied-operations", false, "discard installed deny overrides before applying --deny-operation flags")
	fs.BoolVar(&opts.ReplacePolicy, "replace-policy", false, "replace an existing managed policy")
	fs.BoolVar(&opts.DevTokenFallback, "dev-token-fallback", false, "configure the current GitHub token fallback runtime")
	fs.StringVar(&opts.OperatorID, "operator", "", "operator identity for the protected inbox")
	fs.StringVar(&opts.OperatorSecretFile, "operator-secret-file", "", "file containing the operator inbox secret")
	fs.StringVar(&opts.OperatorEndpoint, "operator-endpoint", "unix:///run/brokerkit/github/operator/broker.sock", "operator inbox endpoint URI")
	fs.StringVar(&opts.TelegramBotTokenFile, "telegram-bot-token-file", "", "file containing the Telegram bot token")
	fs.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram operator chat id")
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
	opts.PolicyPresetExplicit = flagWasProvided(fs, "policy-preset")
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
	operatorSecret, err := bksetup.ResolveSecret(bksetup.SecretInput{File: opts.OperatorSecretFile}, strings.NewReader(""))
	if err != nil {
		return setupSystemdOptions{}, false, err
	}
	opts.OperatorSecret = operatorSecret
	return opts, false, validateSetupSystemdOptions(opts)
}

func validateSetupSystemdOptions(opts setupSystemdOptions) error {
	if err := opts.Validate(); err != nil {
		return err
	}
	if err := validateSetupSystemdCredentialOptions(opts); err != nil {
		return err
	}
	if err := validateSetupSystemdClientOptions(opts); err != nil {
		return err
	}
	if (opts.TelegramBotTokenFile == "") != (opts.TelegramChatID == 0) {
		return errors.New("--telegram-bot-token-file and --telegram-chat-id must be set together")
	}
	if err := validateSetupOperatorCredentials(opts); err != nil {
		return err
	}
	return validateSetupOperatorListener(opts)
}

func validateSetupOperatorCredentials(opts setupSystemdOptions) error {
	if err := clientconfig.ValidateClientName(opts.OperatorID); err != nil {
		return err
	}
	if _, err := bksetup.ResolveSecret(bksetup.SecretInput{Stdin: true}, strings.NewReader(opts.OperatorSecret)); err != nil {
		return fmt.Errorf("operator secret: %w", err)
	}
	if opts.OperatorSecret == opts.SharedSecret {
		return errors.New("operator secret must differ from the client secret")
	}
	return nil
}

func validateSetupOperatorListener(opts setupSystemdOptions) error {
	operatorEndpoint, err := endpoint.Parse(opts.OperatorEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return fmt.Errorf("--operator-endpoint: %w", err)
	}
	if operatorEndpoint.Scheme() == endpoint.SchemeFD {
		return errors.New("--operator-endpoint cannot use a raw inherited descriptor")
	}
	if operatorEndpoint.String() == opts.Endpoint {
		return errors.New("operator and agent endpoints must differ")
	}
	return nil
}

func validateSetupSystemdCredentialOptions(opts setupSystemdOptions) error {
	if err := validateSetupPolicyOptions(opts); err != nil {
		return err
	}
	if opts.DevTokenFallback {
		return validateDevTokenSetup(opts)
	}
	return validateGitHubAppSetup(opts)
}

func validateSetupPolicyOptions(opts setupSystemdOptions) error {
	if opts.ScopeFile != "" {
		if opts.PolicyPresetExplicit || len(opts.DeniedOperations) > 0 || opts.ResetDeniedOperations {
			return errors.New("--scope-file cannot be combined with managed policy preset flags")
		}
		return nil
	}
	if opts.PolicyPreset != policypreset.RequestAllAgentOperations {
		return fmt.Errorf("unknown --policy-preset %q", opts.PolicyPreset)
	}
	if opts.ResetDeniedOperations && !opts.ReplacePolicy {
		return errors.New("--reset-denied-operations requires --replace-policy")
	}
	_, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: opts.PolicyPreset,
		Clients: []string{opts.ClientName}, DeniedOperations: opts.DeniedOperations,
	})
	return err
}

func flagWasProvided(fs *flag.FlagSet, name string) bool {
	provided := false
	fs.Visit(func(found *flag.Flag) { provided = provided || found.Name == name })
	return provided
}

func validateDevTokenSetup(opts setupSystemdOptions) error {
	if opts.GitHubTokenFile == "" {
		return errors.New("--github-token-file is required with --dev-token-fallback")
	}
	return nil
}

func validateGitHubAppSetup(opts setupSystemdOptions) error {
	if err := validateGitHubAppCoreSetup(opts); err != nil {
		return err
	}
	return validateGitHubAppUserSetup(opts)
}

func validateGitHubAppCoreSetup(opts setupSystemdOptions) error {
	if opts.GitHubAppIDFile == "" || opts.GitHubAppPrivateKeyFile == "" || opts.GitHubWebhookSecretFile == "" {
		return errors.New("GitHub App credential files are required unless --dev-token-fallback is set")
	}
	return nil
}

func validateGitHubAppUserSetup(opts setupSystemdOptions) error {
	if (opts.GitHubAppClientIDFile == "") != (opts.GitHubAppClientSecretFile == "") {
		return errors.New("--github-app-client-id-file and --github-app-client-secret-file must be set together")
	}
	if opts.GitHubAppClientIDFile != "" && opts.GitHubUserID <= 0 {
		return errors.New("--github-user-id is required with GitHub App OAuth client credentials")
	}
	if opts.GitHubAppClientIDFile == "" && opts.GitHubUserID != 0 {
		return errors.New("--github-user-id requires GitHub App OAuth client credentials")
	}
	return nil
}

func validateSetupSystemdClientOptions(opts setupSystemdOptions) error {
	_, err := bksetup.ResolveSecret(bksetup.SecretInput{Stdin: true}, strings.NewReader(opts.SharedSecret))
	return err
}
