package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/config"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/brokerkit/credentiallifecycle"
	"github.com/osolmaz/brokerkit/providercredential"
	bkservice "github.com/osolmaz/brokerkit/service"
)

const credentialStatusFileName = "credential-status.json" // #nosec G101 -- this is a metadata filename, not a credential.

type credentialDependencies struct {
	inspect     func(context.Context, string, string, uint64) (providercredential.Snapshot, error)
	replace     func(context.Context, bkservice.CredentialReplacePlan) error
	openURL     func(context.Context, string) error
	readHidden  func(io.Reader, io.Writer) (string, error)
	euid        func() int
	runElevated func(context.Context, string, []string, io.Writer, io.Writer) error
	readFile    func(string) ([]byte, error)
}

type credentialOptions struct {
	jsonOutput bool
	noOpen     bool
	tokenStdin bool
}

type credentialStatus struct {
	Status   string                      `json:"status"`
	Snapshot providercredential.Snapshot `json:"snapshot"`
}

func defaultCredentialDependencies() credentialDependencies {
	return credentialDependencies{
		inspect: func(ctx context.Context, baseURL, token string, generation uint64) (providercredential.Snapshot, error) {
			client := &http.Client{Timeout: 30 * time.Second}
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			secret, err := providercredential.NewSecret([]byte(token))
			if err != nil {
				return providercredential.Snapshot{}, err
			}
			defer secret.Clear()
			return (credentialauth.Adapter{Inspector: credentialauth.Inspector{BaseURL: baseURL, Client: client}, Generation: generation}).Inspect(ctx, secret)
		},
		replace:     bkservice.ReplaceCredential,
		openURL:     openCredentialURL,
		readHidden:  readHiddenCredential,
		euid:        os.Geteuid,
		runElevated: runElevatedCredential,
		readFile:    os.ReadFile,
	}
}

func runCredential(command commandContext, args []string, deps credentialDependencies) error {
	if len(args) == 0 {
		return credentialUsage()
	}
	runner, found := credentialSubcommands[args[0]]
	if !found {
		return credentialUsage()
	}
	return runner(command, args[1:], deps)
}

type credentialSubcommand func(commandContext, []string, credentialDependencies) error

var credentialSubcommands = map[string]credentialSubcommand{
	"inspect": func(command commandContext, args []string, deps credentialDependencies) error {
		return runCredentialInspect(command, args, deps)
	},
	"repair": func(command commandContext, args []string, deps credentialDependencies) error {
		return runCredentialRepair(command, args, deps, false)
	},
	"status": func(command commandContext, args []string, deps credentialDependencies) error {
		return runCredentialStatus(command, args, deps, false)
	},
	"__activate": func(command commandContext, args []string, deps credentialDependencies) error {
		if deps.euid() != 0 {
			return exitError{code: 1, message: "credential activation must run as root"}
		}
		return runCredentialRepair(command, args, deps, true)
	},
	"__status": func(command commandContext, args []string, deps credentialDependencies) error {
		if deps.euid() != 0 {
			return exitError{code: 1, message: "credential status must run as root"}
		}
		return runCredentialStatus(command, args, deps, true)
	},
}

func credentialUsage() error {
	return exitError{code: 64, message: "usage: hf-broker credential <inspect|repair|status> [options]"}
}

func runCredentialInspect(command commandContext, args []string, deps credentialDependencies) error {
	options, err := parseCredentialOptions("inspect", args, false)
	if err != nil {
		return err
	}
	if !options.tokenStdin {
		return exitError{code: 64, message: "credential inspect requires --token-stdin"}
	}
	token, err := readCredentialStdin(command.stdin)
	if err != nil {
		return err
	}
	snapshot, err := deps.inspect(command.ctx, credentialUpstream(command.getenv), token, 1)
	clearString(&token)
	if err != nil {
		return err
	}
	return printCredentialSnapshot(command.stdout, snapshot, options.jsonOutput)
}

func runCredentialRepair(command commandContext, args []string, deps credentialDependencies, activating bool) error {
	options, token, generation, err := prepareCredentialRepair(command, args, deps, activating)
	if err != nil {
		return err
	}
	defer clearString(&token)
	snapshot, err := deps.inspect(command.ctx, credentialUpstream(command.getenv), token, generation)
	if err != nil {
		return err
	}
	return finishCredentialRepair(command, deps, options, token, snapshot, activating)
}

func prepareCredentialRepair(command commandContext, args []string, deps credentialDependencies, activating bool) (credentialOptions, string, uint64, error) {
	options, err := parseCredentialOptions("repair", args, !activating)
	if err != nil {
		return credentialOptions{}, "", 0, err
	}
	if err := validateCredentialRepairInput(options, activating); err != nil {
		return credentialOptions{}, "", 0, err
	}
	if err := presentCredentialRepair(command, options, deps, activating); err != nil {
		return credentialOptions{}, "", 0, err
	}
	token, err := readRepairCredential(command, options, deps)
	if err != nil {
		return credentialOptions{}, "", 0, err
	}
	generation, err := credentialRepairGeneration(deps, activating)
	if err != nil {
		clearString(&token)
		return credentialOptions{}, "", 0, err
	}
	return options, token, generation, nil
}

func validateCredentialRepairInput(options credentialOptions, activating bool) error {
	if activating && !options.tokenStdin {
		return exitError{code: 64, message: "credential activation requires --token-stdin"}
	}
	return nil
}

func presentCredentialRepair(command commandContext, options credentialOptions, deps credentialDependencies, activating bool) error {
	if activating {
		return nil
	}
	return presentCredentialForm(command, options, deps)
}

func credentialRepairGeneration(deps credentialDependencies, activating bool) (uint64, error) {
	if !activating {
		return 1, nil
	}
	return nextCredentialGeneration(deps)
}

func finishCredentialRepair(command commandContext, deps credentialDependencies, options credentialOptions, token string,
	snapshot providercredential.Snapshot, activating bool) error {
	if !activating && deps.euid() != 0 {
		return elevateCredentialRepair(command, options, deps, token)
	}
	if err := activateCredential(command, deps, token, snapshot); err != nil {
		return err
	}
	if options.jsonOutput {
		return json.NewEncoder(command.stdout).Encode(credentialStatus{Status: "valid", Snapshot: snapshot})
	}
	_, err := fmt.Fprintf(command.stdout, "HF Broker credential ready for %s (%d capabilities, generation %d).\n",
		snapshot.Subject, len(snapshot.Capabilities), snapshot.Generation)
	return err
}

func parseCredentialOptions(command string, args []string, allowOpen bool) (credentialOptions, error) {
	var options credentialOptions
	flags := flag.NewFlagSet("credential "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON")
	flags.BoolVar(&options.tokenStdin, "token-stdin", false, "read the token from stdin")
	if allowOpen {
		flags.BoolVar(&options.noOpen, "no-open", false, "do not open the token form")
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return credentialOptions{}, exitError{code: 64, message: "invalid credential " + command + " options"}
	}
	return options, nil
}

func presentCredentialForm(command commandContext, options credentialOptions, deps credentialDependencies) error {
	if !options.noOpen {
		if err := deps.openURL(command.ctx, credentialauth.TokenFormURL); err != nil {
			_, _ = fmt.Fprintln(command.stderr, "Could not open a browser; use the URL printed below.")
		}
	}
	_, err := fmt.Fprintf(command.stdout,
		"Create a dedicated fine-grained Hugging Face token. Choose the permissions and resources this broker may use.\n%s\n",
		credentialauth.TokenFormURL)
	return err
}

func readRepairCredential(command commandContext, options credentialOptions, deps credentialDependencies) (string, error) {
	if options.tokenStdin {
		return readCredentialStdin(command.stdin)
	}
	return deps.readHidden(command.stdin, command.stdout)
}

func readCredentialStdin(stdin io.Reader) (string, error) {
	if stdin == nil {
		return "", errors.New("Hugging Face token input is unavailable") //nolint:staticcheck // Hugging Face is a proper name.
	}
	data, err := io.ReadAll(io.LimitReader(stdin, 64*1024+1))
	if err != nil || len(data) > 64*1024 {
		clear(data)
		return "", errors.New("Hugging Face token input is unavailable or too large") //nolint:staticcheck // Hugging Face is a proper name.
	}
	defer clear(data)
	return credentialauth.NormalizeToken(string(data))
}

func readHiddenCredential(stdin io.Reader, stdout io.Writer) (string, error) {
	file, err := credentialTerminal(stdin)
	if err != nil {
		return "", errors.New("interactive token input requires a terminal; use --token-stdin")
	}
	return readHiddenCredentialFile(file, stdout, term.ReadPassword)
}

func readHiddenCredentialFile(file *os.File, stdout io.Writer, readPassword func(int) ([]byte, error)) (string, error) {
	if _, err := fmt.Fprint(stdout, "Paste the new Hugging Face broker token: "); err != nil {
		return "", err
	}
	data, err := readPassword(int(file.Fd()))
	_, _ = fmt.Fprintln(stdout)
	if err != nil {
		return "", errors.New("read Hugging Face token")
	}
	defer clear(data)
	return credentialauth.NormalizeToken(string(data))
}

func credentialTerminal(stdin io.Reader) (*os.File, error) {
	file, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return nil, errors.New("credential input is not a terminal")
	}
	return file, nil
}

func elevateCredentialRepair(command commandContext, options credentialOptions, deps credentialDependencies, token string) error {
	args := []string{"credential", "__activate", "--token-stdin"}
	if options.jsonOutput {
		args = append(args, "--json")
	}
	return deps.runElevated(command.ctx, token+"\n", args, command.stdout, command.stderr)
}

func runElevatedCredential(ctx context.Context, token string, args []string, stdout, stderr io.Writer) error {
	// #nosec G204 -- args come only from the closed credential subcommand construction above.
	command := exec.CommandContext(ctx, "sudo", append([]string{"--", "/usr/local/bin/hf-broker"}, args...)...)
	command.Stdin = strings.NewReader(token)
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return errors.New("privileged HF Broker credential activation failed")
	}
	return nil
}

func activateCredential(command commandContext, deps credentialDependencies, token string, snapshot providercredential.Snapshot) error {
	deployment := installedCredentialDeployment()
	metadata, err := json.MarshalIndent(credentialStatus{Status: "valid", Snapshot: snapshot}, "", "  ")
	if err != nil {
		return errors.New("encode credential status")
	}
	metadata = append(metadata, '\n')
	reporter, err := credentiallifecycle.New(audit.New(command.stderr), "hf-broker", "local-operator")
	if err != nil {
		return err
	}
	plan := bkservice.CredentialReplacePlan{
		Provider: "huggingface",
		User:     deployment.user, Group: deployment.group, ConfigDir: deployment.configDir,
		SystemdUnit: unitFileName, LaunchdLabel: deployment.launchdLabel,
		Files: []bkservice.ManagedFile{
			{Area: bkservice.ManagedFileConfig, Name: hfTokenFileName, Data: []byte(token + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "huggingface-access"},
			{Area: bkservice.ManagedFileConfig, Name: credentialStatusFileName, Data: metadata, Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot, CredentialClass: "huggingface-access-metadata"},
		},
		ReadyCheck: bkservice.EndpointReadyCheck(deployment.endpoint, "/healthz"), Lifecycle: reporter,
	}
	return deps.replace(command.ctx, plan)
}

type credentialDeployment struct {
	configDir    string
	user         string
	group        string
	endpoint     string
	launchdLabel string
}

func installedCredentialDeployment() credentialDeployment {
	if runtime.GOOS == "darwin" {
		return credentialDeployment{
			configDir: "/Library/Application Support/BrokerKit/hf-broker/config", user: "_hf_broker", group: "_hf_broker",
			endpoint: "unix:///var/run/brokerkit/huggingface/agent/broker.sock", launchdLabel: "dev.brokerkit.huggingface",
		}
	}
	return credentialDeployment{
		configDir: "/etc/hf-broker", user: "hf-broker", group: "hf-broker",
		endpoint: "unix:///run/brokerkit/huggingface/agent/broker.sock",
	}
}

func runCredentialStatus(command commandContext, args []string, deps credentialDependencies, privileged bool) error {
	options, err := parseCredentialOptions("status", args, false)
	if err != nil {
		return err
	}
	if options.tokenStdin {
		return exitError{code: 64, message: "credential status does not accept --token-stdin"}
	}
	if !privileged && deps.euid() != 0 {
		return elevateCredentialStatus(command, deps, options)
	}
	status, err := readCredentialStatus(deps)
	if err != nil {
		return err
	}
	if options.jsonOutput {
		return json.NewEncoder(command.stdout).Encode(status)
	}
	return printCredentialSnapshot(command.stdout, status.Snapshot, false)
}

func elevateCredentialStatus(command commandContext, deps credentialDependencies, options credentialOptions) error {
	args := []string{"credential", "__status"}
	if options.jsonOutput {
		args = append(args, "--json")
	}
	return deps.runElevated(command.ctx, "", args, command.stdout, command.stderr)
}

func readCredentialStatus(deps credentialDependencies) (credentialStatus, error) {
	path := filepath.Join(installedCredentialDeployment().configDir, credentialStatusFileName)
	data, err := deps.readFile(path)
	if err != nil {
		return credentialStatus{}, errors.New("HF Broker credential status is unavailable; run hf-broker credential repair")
	}
	var status credentialStatus
	if err := json.Unmarshal(data, &status); err != nil || status.Status != "valid" || status.Snapshot.CredentialKind != "fine_grained_user_token" {
		return credentialStatus{}, errors.New("HF Broker credential status is invalid; run hf-broker credential repair")
	}
	return status, nil
}

func printCredentialSnapshot(stdout io.Writer, snapshot providercredential.Snapshot, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(stdout).Encode(snapshot)
	}
	_, err := fmt.Fprintf(stdout, "%s: %s, %d capabilities, generation %d, verified %s\n",
		snapshot.Subject, snapshot.CredentialKind, len(snapshot.Capabilities), snapshot.Generation, snapshot.VerifiedAt.Format(time.RFC3339))
	return err
}

func nextCredentialGeneration(deps credentialDependencies) (uint64, error) {
	path := filepath.Join(installedCredentialDeployment().configDir, credentialStatusFileName)
	data, err := deps.readFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 1, nil
		}
		return 0, errors.New("HF Broker credential status could not be read")
	}
	var status credentialStatus
	if json.Unmarshal(data, &status) != nil || status.Status != "valid" || status.Snapshot.Generation == 0 || status.Snapshot.Generation == ^uint64(0) {
		return 0, errors.New("HF Broker credential status is invalid; repair was not applied")
	}
	return status.Snapshot.Generation + 1, nil
}

func credentialUpstream(getenv func(string) string) string {
	if getenv != nil {
		if value := strings.TrimSpace(getenv("HF_BROKER_UPSTREAM_HUB_URL")); value != "" {
			return value
		}
	}
	return config.DefaultUpstreamHubURL
}

func openCredentialURL(ctx context.Context, rawURL string) error {
	name, args, err := browserCommand(rawURL)
	if err != nil {
		return err
	}
	return exec.CommandContext(ctx, name, args...).Start() // #nosec G204 -- command is closed and URL is constant.
}

func browserCommand(rawURL string) (string, []string, error) {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{rawURL}
	case "linux":
		name, args = "xdg-open", []string{rawURL}
	default:
		return "", nil, errors.New("browser opening is not supported")
	}
	return name, args, nil
}

func clearString(value *string) {
	if value == nil {
		return
	}
	buffer := bytes.Repeat([]byte{0}, len(*value))
	*value = string(buffer)
	*value = ""
}
