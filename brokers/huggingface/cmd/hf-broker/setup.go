package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
	"github.com/osolmaz/brokerkit/clientconfig"
	"github.com/osolmaz/brokerkit/credentiallifecycle"
	"github.com/osolmaz/brokerkit/endpoint"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const setupUsage = `usage:
	  hf-broker setup systemd --hf-token-file <path> [--policy-preset request-all-agent-operations] [flags]
	  hf-broker setup systemd --hf-token-file <path> --repo <owner/name> --repo-type <model|dataset|space> [flags]
  hf-broker setup launchd --hf-token-file <path> [--policy-preset request-all-agent-operations] [flags]
  hf-broker setup client --client <name> --endpoint <uri> --secret-file <path> [--home-dir <path>]`

var hubNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type setupSystemdOptions struct {
	bksetup.SystemdOptions
	HFTokenFile           string
	TelegramBotTokenFile  string
	TelegramChatID        int64
	Repo                  string
	RepoType              string
	PolicyPreset          string
	DeniedOperations      stringListFlag
	ResetDeniedOperations bool
	PolicyPresetExplicit  bool
	ReplacePolicy         bool
	SharedSecret          string
	OperatorName          string
	OperatorSecretFile    string
	OperatorSecret        string
	OperatorEndpoint      string
	CommandRunner         bkservice.CommandRunner
	Lifecycle             *credentiallifecycle.Reporter
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
		opts.Lifecycle, err = credentiallifecycle.New(audit.New(stderr), "hf-broker", "local-operator")
		if err != nil {
			return err
		}
		return runSetupSystemd(ctx, stdout, opts)
	case "launchd":
		return runSetupLaunchdCommand(ctx, stdin, stdout, stderr, args[1:])
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
			Endpoint: "unix:///run/brokerkit/huggingface/agent/broker.sock",
		}),
	}
	var flagOutput strings.Builder
	fs := flag.NewFlagSet("hf-broker setup systemd", flag.ContinueOnError)
	fs.SetOutput(&flagOutput)
	bksetup.BindSystemdFlags(fs, &opts.SystemdOptions)
	fs.StringVar(&opts.HFTokenFile, "hf-token-file", "", "file containing the upstream Hugging Face token")
	fs.StringVar(&opts.Repo, "repo", "", "allowed Hub repo as owner/name")
	fs.StringVar(&opts.RepoType, "repo-type", "", "Hub repo type: model, dataset, or space")
	fs.StringVar(&opts.PolicyPreset, "policy-preset", policypreset.RequestAllAgentOperations, "provider-owned policy preset")
	fs.Var(&opts.DeniedOperations, "deny-operation", "exact operation to deny in the preset; repeatable")
	fs.BoolVar(&opts.ResetDeniedOperations, "reset-denied-operations", false, "discard installed deny overrides before applying --deny-operation flags")
	fs.BoolVar(&opts.ReplacePolicy, "replace-policy", false, "replace an existing managed policy")
	fs.StringVar(&opts.TelegramBotTokenFile, "telegram-bot-token-file", "", "file containing the Telegram bot token")
	fs.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram operator chat id")
	fs.StringVar(&opts.OperatorName, "operator", "", "operator identity for the protected inbox")
	fs.StringVar(&opts.OperatorSecretFile, "operator-secret-file", "", "file containing the operator inbox secret")
	fs.StringVar(&opts.OperatorEndpoint, "operator-endpoint", "unix:///run/brokerkit/huggingface/operator/broker.sock", "operator inbox endpoint URI")
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
	opts.PolicyPresetExplicit = flagProvided(fs, "policy-preset")
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
	operatorSecret, err := bksetup.ResolveSecret(bksetup.SecretInput{File: opts.OperatorSecretFile}, strings.NewReader(""))
	if err != nil {
		return setupSystemdOptions{}, exitError{code: 64, message: err.Error()}
	}
	opts.OperatorSecret = operatorSecret
	return opts, validateSetupSystemdOptions(opts)
}

func validateSetupSystemdOptions(opts setupSystemdOptions) error {
	if err := validateSetupRequired(opts); err != nil {
		return err
	}
	if err := opts.Validate(); err != nil {
		return exitError{code: 64, message: err.Error()}
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
	if (opts.TelegramBotTokenFile == "") != (opts.TelegramChatID == 0) {
		return exitError{code: 64, message: "--telegram-bot-token-file and --telegram-chat-id must be set together"}
	}
	return validateOperatorSetup(opts)
}

func validateOperatorSetup(opts setupSystemdOptions) error {
	if err := validateOperatorCredentials(opts); err != nil {
		return err
	}
	return validateOperatorListener(opts)
}

func validateOperatorCredentials(opts setupSystemdOptions) error {
	if err := clientconfig.ValidateClientName(opts.OperatorName); err != nil {
		return exitError{code: 64, message: "invalid --operator: " + err.Error()}
	}
	if len(opts.OperatorSecret) < config.MinSecretBytes {
		return exitError{code: 64, message: fmt.Sprintf("operator secret must be at least %d bytes", config.MinSecretBytes)}
	}
	if subtle.ConstantTimeCompare([]byte(opts.OperatorSecret), []byte(opts.SharedSecret)) == 1 {
		return exitError{code: 64, message: "operator secret must differ from the client secret"}
	}
	return nil
}

func validateOperatorListener(opts setupSystemdOptions) error {
	operatorEndpoint, err := endpoint.Parse(opts.OperatorEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return exitError{code: 64, message: "--operator-endpoint: " + err.Error()}
	}
	if operatorEndpoint.Scheme() == endpoint.SchemeFD {
		return exitError{code: 64, message: "--operator-endpoint cannot use a raw inherited descriptor"}
	}
	if operatorEndpoint.String() == opts.Endpoint {
		return exitError{code: 64, message: "operator and agent endpoints must differ"}
	}
	return nil
}

func validateSetupRepo(opts setupSystemdOptions) error {
	if (opts.Repo == "") != (opts.RepoType == "") {
		return exitError{code: 64, message: "--repo and --repo-type must be set together"}
	}
	if opts.Repo == "" {
		return validateSetupPreset(opts)
	}
	return validateSetupNarrowRepo(opts)
}

func validateSetupPreset(opts setupSystemdOptions) error {
	if opts.PolicyPreset != policypreset.RequestAllAgentOperations {
		return exitError{code: 64, message: fmt.Sprintf("unknown --policy-preset %q", opts.PolicyPreset)}
	}
	if opts.ResetDeniedOperations && !opts.ReplacePolicy {
		return exitError{code: 64, message: "--reset-denied-operations requires --replace-policy"}
	}
	if _, err := policypreset.Render(policypreset.Profile{
		Version: policypreset.ProfileVersion, Preset: opts.PolicyPreset,
		Clients: []string{opts.ClientName}, DeniedOperations: opts.DeniedOperations,
	}); err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	return nil
}

func validateSetupNarrowRepo(opts setupSystemdOptions) error {
	if opts.PolicyPresetExplicit {
		return exitError{code: 64, message: "--policy-preset cannot be combined with --repo and --repo-type"}
	}
	if len(opts.DeniedOperations) > 0 {
		return exitError{code: 64, message: "--deny-operation requires preset policy mode without --repo"}
	}
	if opts.ResetDeniedOperations {
		return exitError{code: 64, message: "--reset-denied-operations requires preset policy mode without --repo"}
	}
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
