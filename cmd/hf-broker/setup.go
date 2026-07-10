package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/clientconfig"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
	"github.com/osolmaz/hf-broker/internal/config"
)

const setupUsage = `usage:
  hf-broker setup systemd --hf-token-file <path> --repo <owner/name> --repo-type <model|dataset|space> [flags]
  hf-broker setup client --client <name> --url <url> --secret-file <path> [--home-dir <path>]`

var hubNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type setupSystemdOptions struct {
	bksetup.SystemdOptions
	HFTokenFile          string
	TelegramBotTokenFile string
	TelegramChatID       int64
	Repo                 string
	RepoType             string
	SharedSecret         string
	OperatorName         string
	OperatorSecretFile   string
	OperatorSecret       string
	OperatorBindAddr     string
	OperatorPort         int
	CommandRunner        bkservice.CommandRunner
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
	fs.StringVar(&opts.TelegramBotTokenFile, "telegram-bot-token-file", "", "file containing the Telegram bot token")
	fs.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram operator chat id")
	fs.StringVar(&opts.OperatorName, "operator", "onur", "operator identity for the protected inbox")
	fs.StringVar(&opts.OperatorSecretFile, "operator-secret-file", "", "file containing the operator inbox secret")
	fs.StringVar(&opts.OperatorBindAddr, "operator-bind-addr", "127.0.0.1", "operator inbox listen address")
	fs.IntVar(&opts.OperatorPort, "operator-port", 8081, "operator inbox listen port")
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
	operatorSecret, err := bksetup.ResolveSecret(bksetup.SecretInput{File: opts.OperatorSecretFile}, strings.NewReader(""))
	if err != nil {
		return setupSystemdOptions{}, exitError{code: 64, message: err.Error()}
	}
	opts.OperatorSecret = operatorSecret
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
	if ip := net.ParseIP(opts.OperatorBindAddr); ip == nil && opts.OperatorBindAddr != "localhost" {
		return exitError{code: 64, message: "--operator-bind-addr must be an IP address or localhost"}
	}
	if opts.OperatorPort < 1 || opts.OperatorPort > 65535 {
		return exitError{code: 64, message: "--operator-port must be between 1 and 65535"}
	}
	if opts.OperatorPort == opts.Port {
		return exitError{code: 64, message: "operator and agent listeners must use different ports"}
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
	switch host {
	case "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, strconv.Itoa(port))
}
