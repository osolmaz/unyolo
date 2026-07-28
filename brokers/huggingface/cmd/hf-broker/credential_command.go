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
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/credentialauth"
	"github.com/osolmaz/unyolo/credential/lifecycle"
	"github.com/osolmaz/unyolo/credential/provider"
	unyoloservice "github.com/osolmaz/unyolo/internal/host/service"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

const (
	credentialStatusFileName = "credential-status.json"     // #nosec G101 -- this is a metadata filename, not a credential.
	credentialAuditFileName  = "credential-lifecycle.jsonl" // #nosec G101 -- this is an audit filename, not a credential.
	maxCredentialStatusBytes = 256 * 1024
	defaultCredentialWidth   = 80
	maxCredentialTextWidth   = 72
)

type credentialDependencies struct {
	inspect       func(context.Context, string, string, uint64) (providercredential.Snapshot, error)
	replace       func(context.Context, unyoloservice.CredentialReplacePlan) error
	openURL       func(context.Context, string) error
	readHidden    func(io.Reader, io.Writer) (string, error)
	euid          func() int
	runElevated   func(context.Context, string, []string, io.Writer, io.Writer) error
	readFile      func(string) ([]byte, error)
	openAudit     func(string, io.Writer) (io.WriteCloser, error)
	terminalWidth func(io.Writer) int
}

type credentialOptions struct {
	jsonOutput bool
	noOpen     bool
	tokenStdin bool
	verbose    bool
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
		replace:       unyoloservice.ReplaceCredential,
		openURL:       openCredentialURL,
		readHidden:    readHiddenCredential,
		euid:          os.Geteuid,
		runElevated:   runElevatedCredential,
		readFile:      os.ReadFile,
		openAudit:     openCredentialAudit,
		terminalWidth: credentialTerminalWidth,
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
	err := runner(command, args[1:], deps)
	if err == nil {
		return nil
	}
	var presented credentialPresentedError
	if errors.As(err, &presented) {
		return exitError{code: presented.code}
	}
	return presentCredentialError(command, args, err)
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
	if !activating && options.jsonOutput && !options.tokenStdin {
		return exitError{code: 64, message: "credential repair --json requires --token-stdin"}
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
	if !activating && deps.euid() != 0 {
		return 1, nil
	}
	return nextCredentialGeneration(deps)
}

func finishCredentialRepair(command commandContext, deps credentialDependencies, options credentialOptions, token string,
	snapshot providercredential.Snapshot, activating bool) error {
	if !activating && deps.euid() != 0 {
		if options.tokenStdin {
			return exitError{code: 1, message: "noninteractive credential repair must run with root privileges; invoke hf-broker through an approved privilege boundary"}
		}
		return elevateCredentialRepair(command, options, deps, token)
	}
	if err := activateCredential(command, deps, options, token, snapshot); err != nil {
		return err
	}
	if options.jsonOutput {
		return json.NewEncoder(command.stdout).Encode(credentialStatus{Status: "valid", Snapshot: snapshot})
	}
	return printCredentialSuccess(command.stdout, snapshot, deps.terminalWidth(command.stdout))
}

func parseCredentialOptions(command string, args []string, allowOpen bool) (credentialOptions, error) {
	var options credentialOptions
	flags := flag.NewFlagSet("credential "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&options.jsonOutput, "json", false, "emit JSON")
	flags.BoolVar(&options.tokenStdin, "token-stdin", false, "read the token from stdin")
	if command == "repair" {
		flags.BoolVar(&options.verbose, "verbose", false, "also print credential lifecycle audit records")
	}
	if allowOpen {
		flags.BoolVar(&options.noOpen, "no-open", false, "do not open the token form")
	}
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return credentialOptions{}, exitError{code: 64, message: "invalid credential " + command + " options"}
	}
	return options, nil
}

func presentCredentialForm(command commandContext, options credentialOptions, deps credentialDependencies) error {
	if options.jsonOutput || options.tokenStdin {
		return nil
	}
	browserOpened := options.noOpen || deps.openURL(command.ctx, credentialauth.TokenFormURL) == nil
	if err := writeCredentialForm(command.stdout, deps.terminalWidth(command.stdout)); err != nil {
		return err
	}
	if !browserOpened {
		_, _ = fmt.Fprintln(command.stderr, "Browser opening was unavailable. Open the URL shown above.")
	}
	return nil
}

func writeCredentialForm(output io.Writer, width int) error {
	if _, err := io.WriteString(output, "Hugging Face credential repair\n\n"); err != nil {
		return err
	}
	if err := writeWrappedCredentialText(output,
		"Create a dedicated fine-grained token for HF Broker. Choose only the permissions and resources this broker may use.", width); err != nil {
		return err
	}
	_, err := fmt.Fprintf(output, "\nOpen this page in your browser:\n%s\n\n", credentialauth.TokenFormURL)
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
	if _, err := fmt.Fprint(stdout, "Hugging Face token (input hidden): "); err != nil {
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
	if options.verbose {
		args = append(args, "--verbose")
	}
	return deps.runElevated(command.ctx, token+"\n", args, command.stdout, command.stderr)
}

func runElevatedCredential(ctx context.Context, token string, args []string, stdout, stderr io.Writer) error {
	// #nosec G204 -- args come only from the closed credential subcommand construction above.
	command := exec.CommandContext(ctx, "sudo", append([]string{"--", "/usr/local/bin/hf-broker"}, args...)...)
	command.Stdin = strings.NewReader(token)
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return elevatedCredentialRunError(err)
	}
	return nil
}

func elevatedCredentialRunError(err error) error {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return credentialPresentedError{code: exit.ExitCode()}
	}
	return errors.New("privileged HF Broker credential activation failed")
}

func activateCredential(command commandContext, deps credentialDependencies, options credentialOptions, token string, snapshot providercredential.Snapshot) (resultErr error) {
	deployment := installedCredentialDeployment()
	metadata, err := json.MarshalIndent(credentialStatus{Status: "valid", Snapshot: snapshot}, "", "  ")
	if err != nil {
		return errors.New("encode credential status")
	}
	metadata = append(metadata, '\n')
	var verboseOutput io.Writer
	if options.verbose {
		verboseOutput = command.stderr
	}
	auditOutput, err := deps.openAudit(deployment.configDir, verboseOutput)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, auditOutput.Close()) }()
	reporter, err := credentiallifecycle.New(audit.New(auditOutput), "hf-broker", "local-operator")
	if err != nil {
		return err
	}
	plan := unyoloservice.CredentialReplacePlan{
		Provider: "huggingface",
		User:     deployment.user, Group: deployment.group, ConfigDir: deployment.configDir,
		SystemdUnit: unitFileName, LaunchdLabel: deployment.launchdLabel,
		Files: []unyoloservice.ManagedFile{
			{Area: unyoloservice.ManagedFileConfig, Name: hfTokenFileName, Data: []byte(token + "\n"), Mode: 0o600, Owner: unyoloservice.ManagedFileOwnerService, CredentialClass: "huggingface-access"},
			{Area: unyoloservice.ManagedFileConfig, Name: credentialStatusFileName, Data: metadata, Mode: 0o640, Owner: unyoloservice.ManagedFileOwnerRoot, CredentialClass: "huggingface-access-metadata"},
		},
		ReadyCheck: unyoloservice.EndpointReadyCheck(deployment.endpoint, "/healthz"), Lifecycle: reporter,
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
			configDir: "/Library/Application Support/unyolo/hf-broker/config", user: "_hf_broker", group: "_hf_broker",
			endpoint: "unix:///var/run/unyolo/huggingface/agent/broker.sock", launchdLabel: "io.unyolo.huggingface",
		}
	}
	return credentialDeployment{
		configDir: "/etc/hf-broker", user: "hf-broker", group: "hf-broker",
		endpoint: "unix:///run/unyolo/huggingface/agent/broker.sock",
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

func printCredentialSuccess(stdout io.Writer, snapshot providercredential.Snapshot, width int) error {
	panelWidth := normalizedCredentialWidth(width)
	if panelWidth > 56 {
		panelWidth = 56
	}
	innerWidth := panelWidth - 4
	rows := []string{"Credential ready"}
	rows = append(rows, credentialPanelRows("Subject: ", snapshot.Subject, innerWidth)...)
	rows = append(rows, fmt.Sprintf("Capabilities: %d", len(snapshot.Capabilities)))
	border := "+" + strings.Repeat("-", panelWidth-2) + "+\n"
	if _, err := io.WriteString(stdout, "\n"+border); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintf(stdout, "| %-*s |\n", innerWidth, row); err != nil {
			return err
		}
	}
	_, err := io.WriteString(stdout, border)
	return err
}

func credentialPanelRows(prefix, value string, width int) []string {
	if width <= len(prefix) {
		return []string{prefix}
	}
	remaining := []rune(value)
	firstWidth := width - len(prefix)
	first := min(len(remaining), firstWidth)
	rows := []string{prefix + string(remaining[:first])}
	remaining = remaining[first:]
	for len(remaining) > 0 {
		end := min(len(remaining), width)
		rows = append(rows, string(remaining[:end]))
		remaining = remaining[end:]
	}
	return rows
}

func writeWrappedCredentialText(output io.Writer, text string, width int) error {
	width = normalizedCredentialWidth(width)
	words := strings.Fields(text)
	line := ""
	for _, word := range words {
		if line != "" && len(line)+1+len(word) > width {
			if _, err := fmt.Fprintln(output, line); err != nil {
				return err
			}
			line = word
			continue
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line == "" {
		return nil
	}
	_, err := fmt.Fprintln(output, line)
	return err
}

func normalizedCredentialWidth(width int) int {
	if width <= 0 {
		width = defaultCredentialWidth
	}
	if width > maxCredentialTextWidth {
		width = maxCredentialTextWidth
	}
	if width < 24 {
		width = 24
	}
	return width
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

type credentialPresentedError struct{ code int }

func (err credentialPresentedError) Error() string { return "credential error was already presented" }

type credentialJSONError struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Error         struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func presentCredentialError(command commandContext, args []string, cause error) error {
	code := credentialErrorExitCode(cause)
	errorCode, message := safeCredentialError(cause)
	if credentialFlagPresent(args[1:], "--json") {
		output := credentialJSONError{SchemaVersion: 1, Status: "error"}
		output.Error.Code, output.Error.Message = errorCode, message
		if err := json.NewEncoder(command.stdout).Encode(output); err != nil {
			return err
		}
		return exitError{code: code}
	}
	if args[0] == "repair" {
		heading := "Credential repair failed"
		if credentialFailureLeavesActiveUnchanged(errorCode) {
			heading = "Credential not changed"
		}
		return exitError{code: code, message: heading + "\n\n" + message}
	}
	return cause
}

func credentialFailureLeavesActiveUnchanged(code string) bool {
	switch code {
	case "credential_usage_invalid", "credential_privilege_required", "credential_input_invalid",
		"credential_kind_unsupported", "credential_authentication_failed", "credential_provider_unavailable",
		"credential_status_invalid", "credential_status_unavailable":
		return true
	default:
		return false
	}
}

func credentialErrorExitCode(err error) int {
	var value exitError
	if errors.As(err, &value) {
		return value.code
	}
	return 1
}

type credentialSafeError struct {
	code    string
	message string
}

var credentialSafeErrors = map[string]credentialSafeError{
	"credential activation requires --token-stdin": {code: "credential_usage_invalid"},
	"credential inspect requires --token-stdin":    {code: "credential_usage_invalid"},
	"credential repair --json requires --token-stdin": {
		code: "credential_usage_invalid",
	},
	"invalid credential inspect options":              {code: "credential_usage_invalid"},
	"invalid credential repair options":               {code: "credential_usage_invalid"},
	"invalid credential status options":               {code: "credential_usage_invalid"},
	"credential status does not accept --token-stdin": {code: "credential_usage_invalid"},
	"noninteractive credential repair must run with root privileges; invoke hf-broker through an approved privilege boundary": {
		code: "credential_privilege_required",
	},
	"Hugging Face token is required":                                 {code: "credential_input_invalid"},
	"Hugging Face token has an invalid format":                       {code: "credential_input_invalid"},
	"Hugging Face token exceeds the size limit":                      {code: "credential_input_invalid"},
	"Hugging Face token input is unavailable":                        {code: "credential_input_invalid"},
	"Hugging Face token input is unavailable or too large":           {code: "credential_input_invalid"},
	"interactive token input requires a terminal; use --token-stdin": {code: "credential_input_invalid"},
	"HF Broker requires a dedicated fine-grained Hugging Face token": {
		code: "credential_kind_unsupported", message: "HF Broker requires a dedicated fine-grained Hugging Face token. Create one with the URL shown above and try again.",
	},
	"Hugging Face did not accept this token": {
		code: "credential_authentication_failed", message: "Hugging Face did not accept this token. Check the token and try again.",
	},
	"Hugging Face credential inspection was rate limited": {
		code: "credential_provider_unavailable", message: "Hugging Face could not validate the token right now. Try again later.",
	},
	"Hugging Face credential inspection is unavailable": {
		code: "credential_provider_unavailable", message: "Hugging Face could not validate the token right now. Try again later.",
	},
	"HF Broker credential status is invalid; run hf-broker credential repair": {
		code: "credential_status_invalid",
	},
	"HF Broker credential status is invalid; repair was not applied": {
		code: "credential_status_invalid",
	},
	"HF Broker credential status is unavailable; run hf-broker credential repair": {
		code: "credential_status_unavailable",
	},
}

func safeCredentialError(err error) (string, string) {
	message := err.Error()
	classified, found := credentialSafeErrors[message]
	if !found {
		return "credential_repair_failed", "HF Broker could not validate or install the credential. The token was not exposed."
	}
	if classified.message == "" {
		classified.message = message
	}
	return classified.code, classified.message
}

func credentialFlagPresent(args []string, wanted string) bool {
	short := strings.TrimPrefix(wanted, "--")
	for _, arg := range args {
		name, rawValue, hasValue := strings.Cut(arg, "=")
		if name != wanted && name != "-"+short {
			continue
		}
		if !hasValue {
			return true
		}
		value, err := strconv.ParseBool(rawValue)
		return err == nil && value
	}
	return false
}

func credentialTerminalWidth(output io.Writer) int {
	file, ok := output.(*os.File)
	if !ok || !term.IsTerminal(int(file.Fd())) {
		return defaultCredentialWidth
	}
	width, _, err := term.GetSize(int(file.Fd()))
	if err != nil {
		return defaultCredentialWidth
	}
	return width
}

type credentialAuditOutput struct {
	root    *os.Root
	file    *os.File
	verbose io.Writer
}

func openCredentialAudit(configDir string, verbose io.Writer) (io.WriteCloser, error) {
	root, err := os.OpenRoot(configDir)
	if err != nil {
		return nil, errors.New("open credential lifecycle audit directory")
	}
	file, err := root.OpenFile(credentialAuditFileName, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		_ = root.Close()
		return nil, errors.New("open credential lifecycle audit log")
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = root.Close()
		return nil, errors.New("secure credential lifecycle audit log")
	}
	return &credentialAuditOutput{root: root, file: file, verbose: verbose}, nil
}

func (output *credentialAuditOutput) Write(data []byte) (int, error) {
	written, err := output.file.Write(data)
	if err != nil {
		return written, err
	}
	if err := output.file.Sync(); err != nil {
		return written, err
	}
	if output.verbose != nil {
		_, _ = output.verbose.Write(data)
	}
	return written, nil
}

func (output *credentialAuditOutput) Close() error {
	return errors.Join(output.file.Sync(), output.file.Close(), output.root.Close())
}

func clearString(value *string) {
	if value == nil {
		return
	}
	buffer := bytes.Repeat([]byte{0}, len(*value))
	*value = string(buffer)
	*value = ""
}
