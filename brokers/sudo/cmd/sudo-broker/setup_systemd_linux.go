//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	unyolopolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/catalog"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/unyolo/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/unyolo/credential/lifecycle"
	"github.com/osolmaz/unyolo/internal/config/client"
	unyoloservice "github.com/osolmaz/unyolo/internal/host/service"
	unyolosetup "github.com/osolmaz/unyolo/internal/host/setup"
	"github.com/osolmaz/unyolo/telemetry/audit"
	"github.com/osolmaz/unyolo/transport/endpoint"
)

const maxSetupFileBytes = 16 << 20

type sudoSystemdOptions struct {
	unyolosetup.SystemdOptions
	PolicyFile           string
	CatalogFile          string
	HelperBinary         string
	HelperStateDir       string
	HelperSocket         string
	SharedSecret         string
	OperatorID           string
	OperatorSecretFile   string
	OperatorSecret       string
	OperatorEndpoint     string
	TelegramBotTokenFile string
	TelegramChatID       int64
	Lifecycle            *credentiallifecycle.Reporter
	helperManaged        bool
}

type sudoInstallPaths struct {
	policy, catalog, secrets, operators, telegram, frontendEnv, helperEnv string
}

func runSetupSystemd(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	opts, help, err := parseSudoSystemdOptions(args, stderr, os.Stdin)
	if err != nil || help {
		return err
	}
	if err := requireSetupPrivileges(opts); err != nil {
		return err
	}
	opts.Lifecycle, err = newSetupLifecycle(stderr)
	if err != nil {
		return err
	}
	paths := sudoPaths(opts)
	helperPlan, frontendPlan, err := sudoInstallPlans(opts, paths)
	if err != nil {
		return err
	}
	return finishSetupSystemd(ctx, stdout, opts, paths, helperPlan, frontendPlan)
}

func requireSetupPrivileges(opts sudoSystemdOptions) error {
	if os.Geteuid() != 0 && !opts.DryRun {
		return errors.New("setup systemd must run as root; try sudo sudo-broker setup systemd")
	}
	return nil
}

func newSetupLifecycle(stderr io.Writer) (*credentiallifecycle.Reporter, error) {
	return credentiallifecycle.New(audit.New(stderr), "sudo-broker", "local-operator")
}

func finishSetupSystemd(ctx context.Context, stdout io.Writer, opts sudoSystemdOptions, paths sudoInstallPaths, helperPlan unyoloservice.SystemdInstallPlan, frontendPlan unyoloservice.SystemdInstallPlan) error {
	if opts.DryRun {
		return printSudoSystemdPlan(stdout, opts, paths, helperPlan, frontendPlan)
	}
	if err := installSudoSystemd(ctx, helperPlan, frontendPlan); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "sudo-broker installed\n  broker endpoint: %s\n  operator endpoint: %s\n  helper socket: %s\n  client secrets: %s\n",
		opts.Endpoint, opts.OperatorEndpoint, opts.HelperSocket, paths.secrets)
	return err
}

func installSudoSystemd(ctx context.Context, helperPlan unyoloservice.SystemdInstallPlan, frontendPlan unyoloservice.SystemdInstallPlan) error {
	return installSudoSystemdWith(ctx, helperPlan, frontendPlan, unyoloservice.InstallSystemd)
}

func installSudoSystemdWith(ctx context.Context, helperPlan unyoloservice.SystemdInstallPlan, frontendPlan unyoloservice.SystemdInstallPlan,
	install func(context.Context, unyoloservice.SystemdInstallPlan) error) error {
	if err := install(ctx, helperPlan); err != nil {
		return fmt.Errorf("install privileged helper: %w", err)
	}
	if err := install(ctx, frontendPlan); err != nil {
		return fmt.Errorf("install unprivileged frontend: %w", err)
	}
	return nil
}

func parseSudoSystemdOptions(args []string, stderr io.Writer, stdin io.Reader) (sudoSystemdOptions, bool, error) {
	common := unyolosetup.DefaultSystemdOptions(unyolosetup.SystemdDefaults{
		BrokerName: "sudo-broker", User: "sudo-broker", Group: "sudo-broker", Endpoint: "unix:///run/unyolo/sudo/agent/broker.sock",
	})
	common.StateDir = "/var/lib/sudo-broker/frontend"
	opts := sudoSystemdOptions{SystemdOptions: common, HelperStateDir: "/var/lib/sudo-broker/helper",
		HelperSocket: "/run/sudo-broker/helper.sock", OperatorEndpoint: "unix:///run/unyolo/sudo/operator/broker.sock"}
	var output strings.Builder
	flags := flag.NewFlagSet("sudo-broker setup systemd", flag.ContinueOnError)
	flags.SetOutput(&output)
	unyolosetup.BindSystemdFlags(flags, &opts.SystemdOptions)
	flags.StringVar(&opts.PolicyFile, "policy-file", "", "sudo policy JSON source")
	flags.StringVar(&opts.CatalogFile, "catalog-file", "", "root-reviewed command catalog source")
	flags.StringVar(&opts.HelperBinary, "helper-binary", "", "sudo-broker-exec binary path")
	flags.StringVar(&opts.HelperStateDir, "helper-state-dir", opts.HelperStateDir, "root-owned helper state directory")
	flags.StringVar(&opts.HelperSocket, "helper-socket", opts.HelperSocket, "frontend-to-helper Unix socket")
	flags.StringVar(&opts.OperatorID, "operator", opts.OperatorID, "operator identity")
	flags.StringVar(&opts.OperatorSecretFile, "operator-secret-file", "", "operator secret source")
	flags.StringVar(&opts.OperatorEndpoint, "operator-endpoint", opts.OperatorEndpoint, "operator endpoint URI")
	flags.StringVar(&opts.TelegramBotTokenFile, "telegram-bot-token-file", "", "Telegram bot token source")
	flags.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram approval chat id")
	if err := flags.Parse(args); err != nil {
		return handleSudoSystemdParseError(err, stderr, output.String())
	}
	if flags.NArg() != 0 {
		return sudoSystemdOptions{}, false, errors.New("setup systemd does not accept positional arguments")
	}
	if err := finalizeSudoSystemdOptions(&opts); err != nil {
		return sudoSystemdOptions{}, false, err
	}
	if err := resolveSudoSystemdSecrets(&opts, stdin); err != nil {
		return sudoSystemdOptions{}, false, err
	}
	return opts, false, validateSudoSystemdOptions(opts)
}

func handleSudoSystemdParseError(err error, stderr io.Writer, output string) (sudoSystemdOptions, bool, error) {
	if errors.Is(err, flag.ErrHelp) {
		_, _ = io.Copy(stderr, strings.NewReader(output))
		return sudoSystemdOptions{}, true, nil
	}
	return sudoSystemdOptions{}, false, errors.New("invalid setup systemd flags")
}

func finalizeSudoSystemdOptions(opts *sudoSystemdOptions) error {
	finalized, err := unyolosetup.FinalizeSystemd(opts.SystemdOptions)
	if err != nil {
		return err
	}
	opts.SystemdOptions = finalized
	if opts.HelperBinary == "" {
		opts.HelperBinary = defaultSudoHelperBinary(opts.BinaryPath)
	}
	return finalizeSudoHelperBinary(opts)
}

func defaultSudoHelperBinary(frontend string) string {
	if frontend == unyolosetup.ManagedExecutablePath(filepath.Join("bin", "sudo-broker")) {
		return unyolosetup.ManagedExecutablePath(filepath.Join("libexec", "sudo-broker-exec"))
	}
	return defaultHelperBinary(frontend)
}

func finalizeSudoHelperBinary(opts *sudoSystemdOptions) error {
	resolvedHelper, managed, err := unyolosetup.ResolveServiceExecutable(opts.HelperBinary, filepath.Join("libexec", "sudo-broker-exec"), opts.AllowNonRoot)
	if err != nil {
		return fmt.Errorf("resolve helper binary: %w", err)
	}
	if os.Geteuid() == 0 && !opts.AllowNonRoot && !opts.DryRun && !managed {
		return errors.New("production helper must use the unYOLO managed current release path")
	}
	opts.HelperBinary = resolvedHelper
	opts.helperManaged = managed
	return nil
}

func resolveSudoSystemdSecrets(opts *sudoSystemdOptions, stdin io.Reader) error {
	var err error
	opts.SharedSecret, err = unyolosetup.ResolveSecret(unyolosetup.SecretInput{File: opts.SharedSecretFile, Stdin: opts.SharedSecretStdin}, stdin)
	if err != nil {
		return err
	}
	opts.OperatorSecret, err = unyolosetup.ResolveSecret(unyolosetup.SecretInput{File: opts.OperatorSecretFile}, strings.NewReader(""))
	return err
}

func defaultHelperBinary(frontend string) string {
	beside := filepath.Join(filepath.Dir(frontend), "sudo-broker-exec")
	if info, err := os.Stat(beside); err == nil && info.Mode().IsRegular() {
		return beside
	}
	return "/usr/local/libexec/sudo-broker-exec"
}

func validateSudoSystemdOptions(opts sudoSystemdOptions) error {
	if err := validateSetupRequiredOptions(opts); err != nil {
		return err
	}
	if err := validateHelperPaths(opts); err != nil {
		return err
	}
	if err := validateSetupStateSeparation(opts); err != nil {
		return err
	}
	if err := validateOperatorEndpoint(opts); err != nil {
		return err
	}
	return validateSetupCredentialsAndHelper(opts)
}

func validateSetupRequiredOptions(opts sudoSystemdOptions) error {
	if opts.PolicyFile == "" || opts.CatalogFile == "" {
		return errors.New("--policy-file and --catalog-file are required")
	}
	if opts.AllowNonRoot && !opts.DryRun {
		return errors.New("sudo-broker systemd setup does not support non-root installation")
	}
	return nil
}

func validateSetupStateSeparation(opts sudoSystemdOptions) error {
	if opts.HelperStateDir == opts.StateDir {
		return errors.New("helper and frontend state directories must differ")
	}
	return nil
}

func validateHelperPaths(opts sudoSystemdOptions) error {
	for name, value := range map[string]string{"helper binary": opts.HelperBinary, "helper state": opts.HelperStateDir, "helper socket": opts.HelperSocket} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute normalized path", name)
		}
	}
	return nil
}

func validateOperatorEndpoint(opts sudoSystemdOptions) error {
	operatorEndpoint, err := endpoint.Parse(opts.OperatorEndpoint, endpoint.ParseOptions{})
	if err != nil {
		return fmt.Errorf("operator endpoint: %w", err)
	}
	if operatorEndpoint.Scheme() == endpoint.SchemeFD || operatorEndpoint.String() == opts.Endpoint {
		return errors.New("agent and operator endpoints must be distinct named endpoints")
	}
	return nil
}

func validateSetupCredentialsAndHelper(opts sudoSystemdOptions) error {
	if err := clientconfig.ValidateClientName(opts.OperatorID); err != nil {
		return err
	}
	if opts.OperatorSecret == opts.SharedSecret {
		return errors.New("operator secret must differ from the client secret")
	}
	if err := validateTelegramSetup(opts); err != nil {
		return err
	}
	return validateTrustedHelperBinary(opts)
}

func validateTelegramSetup(opts sudoSystemdOptions) error {
	if (opts.TelegramBotTokenFile == "") != (opts.TelegramChatID == 0) {
		return errors.New("--telegram-bot-token-file and --telegram-chat-id must be configured together")
	}
	return nil
}

func validateTrustedHelperBinary(opts sudoSystemdOptions) error {
	return validateTrustedHelperBinaryWith(opts, os.Geteuid(), hostcheck.ValidateRootFile)
}

func validateTrustedHelperBinaryWith(opts sudoSystemdOptions, effectiveUID int, validateRootFile func(string) error) error {
	if effectiveUID != 0 || opts.DryRun || opts.helperManaged {
		return nil
	}
	if err := validateRootFile(opts.HelperBinary); err != nil {
		return fmt.Errorf("helper binary is not trusted: %w", err)
	}
	return nil
}

func sudoPaths(opts sudoSystemdOptions) sudoInstallPaths {
	return sudoInstallPaths{
		policy: filepath.Join(opts.ConfigDir, "policy.json"), catalog: filepath.Join(opts.ConfigDir, "catalog.json"),
		secrets: filepath.Join(opts.ConfigDir, "secrets"), operators: filepath.Join(opts.ConfigDir, "operator-secrets"),
		telegram: filepath.Join(opts.ConfigDir, "telegram-bot-token"), frontendEnv: filepath.Join(opts.ConfigDir, "frontend.env"),
		helperEnv: filepath.Join(opts.ConfigDir, "helper.env"),
	}
}

func sudoInstallPlans(opts sudoSystemdOptions, paths sudoInstallPaths) (unyoloservice.SystemdInstallPlan, unyoloservice.SystemdInstallPlan, error) {
	activation, err := unyolosetup.BuildSystemdActivation(opts.SystemdOptions, opts.OperatorEndpoint, "sudo-broker.service")
	if err != nil {
		return unyoloservice.SystemdInstallPlan{}, unyoloservice.SystemdInstallPlan{}, err
	}
	catalogData, policyData, err := validatedSetupSources(opts)
	if err != nil {
		return unyoloservice.SystemdInstallPlan{}, unyoloservice.SystemdInstallPlan{}, err
	}
	pathValidation := unyoloservice.PathValidationStrict
	if opts.DryRun {
		pathValidation = unyoloservice.PathValidationPreview
	}
	helperUnit := helperSystemdUnit(opts, paths, pathValidation)
	frontendUnit := frontendSystemdUnit(opts, paths, pathValidation)
	sharedStateDir := sharedStateDirectory(opts.StateDir, opts.HelperStateDir)
	helperPlan := unyoloservice.SystemdInstallPlan{User: "root", Group: opts.Group, ConfigDir: opts.ConfigDir, StateDir: opts.HelperStateDir, SharedStateDir: sharedStateDir,
		SystemdDir: opts.SystemdDir, UnitName: "sudo-broker-exec.service", NoStart: true, Unit: helperUnit,
		Files: []unyoloservice.ManagedFile{
			{Area: unyoloservice.ManagedFileConfig, Name: "catalog.json", Data: catalogData, Mode: 0o640, Owner: unyoloservice.ManagedFileOwnerRoot},
			{Area: unyoloservice.ManagedFileConfig, Name: "helper.env", Data: []byte("# managed by sudo-broker\n"), Mode: 0o640, Owner: unyoloservice.ManagedFileOwnerRoot},
		}}
	frontendFiles := []unyoloservice.ManagedFile{
		{Area: unyoloservice.ManagedFileConfig, Name: "policy.json", Data: policyData, Mode: 0o640, Owner: unyoloservice.ManagedFileOwnerRoot},
		frontendSecretFile("secrets", []byte(opts.ClientName+" = "+opts.SharedSecret+"\n")),
		frontendSecretFile("operator-secrets", []byte(opts.OperatorID+" = "+opts.OperatorSecret+"\n")),
		{Area: unyoloservice.ManagedFileConfig, Name: "frontend.env", Data: []byte("# managed by sudo-broker\n"), Mode: 0o640, Owner: unyoloservice.ManagedFileOwnerRoot},
	}
	if opts.TelegramBotTokenFile != "" {
		data, readErr := readSetupFile(opts.TelegramBotTokenFile)
		if readErr != nil {
			return unyoloservice.SystemdInstallPlan{}, unyoloservice.SystemdInstallPlan{}, readErr
		}
		frontendFiles = append(frontendFiles, frontendSecretFile("telegram-bot-token", data))
	}
	var removeFiles []unyoloservice.ManagedFileRef
	if opts.TelegramBotTokenFile == "" {
		removeFiles = append(removeFiles, unyoloservice.ManagedFileRef{Area: unyoloservice.ManagedFileConfig, Name: "telegram-bot-token", CredentialClass: "telegram-bot"})
	}
	frontendPlan := unyoloservice.SystemdInstallPlan{User: opts.User, Group: opts.Group, ConfigDir: opts.ConfigDir, StateDir: opts.StateDir, SharedStateDir: sharedStateDir,
		SystemdDir: opts.SystemdDir, UnitName: "sudo-broker.service", NoStart: opts.NoStart, Unit: frontendUnit, Files: frontendFiles, RemoveFiles: removeFiles,
		AdditionalGroups: activation.Groups, GroupMembers: activation.GroupMembers, SocketUnits: activation.Sockets,
		ActivationUnits: activation.ActivationUnits, ReadyCheck: unyoloservice.EndpointReadyCheck(opts.Endpoint, "/readyz"), Lifecycle: opts.Lifecycle}
	return helperPlan, frontendPlan, nil
}

func validatedSetupSources(opts sudoSystemdOptions) ([]byte, []byte, error) {
	snapshot, err := catalog.Load(opts.CatalogFile)
	if err != nil {
		return nil, nil, err
	}
	if _, err := unyolopolicy.LoadFile(opts.PolicyFile, sudopolicy.Registry(snapshot)); err != nil {
		return nil, nil, err
	}
	catalogData, err := readSetupFile(opts.CatalogFile)
	if err != nil {
		return nil, nil, err
	}
	policyData, err := readSetupFile(opts.PolicyFile)
	if err != nil {
		return nil, nil, err
	}
	return catalogData, policyData, nil
}

func helperSystemdUnit(opts sudoSystemdOptions, paths sudoInstallPaths, pathValidation unyoloservice.PathValidation) unyoloservice.SystemdUnit {
	return unyoloservice.SystemdUnit{Description: "sudo-broker privileged command executor", User: "root", Group: opts.Group,
		EnvironmentFile: paths.helperEnv, ExecStart: strings.Join([]string{opts.HelperBinary, "--catalog", paths.catalog, "--state", filepath.Join(opts.HelperStateDir, "executions.json"), "--socket", opts.HelperSocket, "--broker-user", opts.User}, " "),
		StateDir: opts.HelperStateDir, ConfigDir: opts.ConfigDir, PrivilegeEscalation: unyoloservice.PrivilegeEscalationAllow,
		PathValidation: pathValidation, RuntimeDirectory: "sudo-broker", RuntimeDirectoryMode: 0o750,
		ManagedExecutableDestination: unyolosetup.ManagedDestination(opts.HelperBinary, filepath.Join("libexec", "sudo-broker-exec")),
		ExtraDirectives:              hardeningDirectives(false)}
}

func frontendSystemdUnit(opts sudoSystemdOptions, paths sudoInstallPaths, pathValidation unyoloservice.PathValidation) unyoloservice.SystemdUnit {
	return unyoloservice.SystemdUnit{Description: "sudo-broker approval frontend", User: opts.User, Group: opts.Group,
		EnvironmentFile: paths.frontendEnv, ExecStart: frontendExec(opts, paths), StateDir: opts.StateDir, ConfigDir: opts.ConfigDir,
		PathValidation: pathValidation, AfterUnits: []string{"sudo-broker-exec.service"}, RequiresUnits: []string{"sudo-broker-exec.service"},
		ManagedExecutableDestination: unyolosetup.ManagedDestination(opts.BinaryPath, opts.ManagedDestination),
		ExtraDirectives:              hardeningDirectives(true)}
}

func sharedStateDirectory(frontend string, helper string) string {
	parent := filepath.Dir(frontend)
	if parent != filepath.Dir(helper) || strings.Count(strings.Trim(parent, string(filepath.Separator)), string(filepath.Separator)) < 2 {
		return ""
	}
	return parent
}

func frontendSecretFile(name string, data []byte) unyoloservice.ManagedFile {
	classes := map[string]string{"secrets": "broker-client", "operator-secrets": "broker-operator", "telegram-bot-token": "telegram-bot"}
	return unyoloservice.ManagedFile{Area: unyoloservice.ManagedFileConfig, Name: name, Data: data, Mode: 0o640, Owner: unyoloservice.ManagedFileOwnerRoot, CredentialClass: classes[name]}
}

func frontendExec(opts sudoSystemdOptions, paths sudoInstallPaths) string {
	values := []string{opts.BinaryPath, "serve", "--policy", paths.policy, "--catalog", paths.catalog, "--secrets", paths.secrets,
		"--operator-secrets", paths.operators, "--state", opts.StateDir,
		"--helper-socket", opts.HelperSocket, "--agent-endpoint", "activation://agent",
		"--operator-endpoint", "activation://operator"}
	if opts.TelegramBotTokenFile != "" {
		values = append(values, "--telegram-token-file", paths.telegram, "--telegram-chat-id", strconv.FormatInt(opts.TelegramChatID, 10))
	}
	return strings.Join(values, " ")
}

func hardeningDirectives(restrictSUID bool) []string {
	values := []string{"LockPersonality=true", "PrivateDevices=true", "ProtectClock=true", "ProtectControlGroups=true", "ProtectHostname=true",
		"ProtectKernelLogs=true", "ProtectKernelModules=true", "ProtectKernelTunables=true", "RemoveIPC=true", "RestrictNamespaces=true",
		"RestrictRealtime=true", "SystemCallArchitectures=native", "UMask=0077"}
	if restrictSUID {
		values = append(values, "RestrictSUIDSGID=true")
	}
	return values
}

func readSetupFile(path string) ([]byte, error) {
	file, err := os.Open(path) // #nosec G304 -- setup source selected by root operator.
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxSetupFileBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(data) == 0 || len(data) > maxSetupFileBytes {
		return nil, errors.New("setup source file is empty or too large")
	}
	return data, nil
}

func printSudoSystemdPlan(stdout io.Writer, opts sudoSystemdOptions, paths sudoInstallPaths, helper unyoloservice.SystemdInstallPlan, frontend unyoloservice.SystemdInstallPlan) error {
	helperUnit, err := unyoloservice.RenderSystemd(helper.Unit)
	if err != nil {
		return err
	}
	frontendUnit, err := unyoloservice.RenderSystemd(frontend.Unit)
	if err != nil {
		return err
	}
	sockets, err := unyoloservice.RenderSystemdSockets(frontend.SocketUnits)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Would install sudo-broker\n  frontend user: %s\n  frontend state: %s\n  helper user: root\n  helper state: %s\n  helper socket: %s\n  policy: %s\n  catalog: %s\n  agent access: %s (%s)\n  operator access: %s (%s)\n\n%s\n%s%s", opts.User, opts.StateDir, opts.HelperStateDir, opts.HelperSocket, paths.policy, paths.catalog, opts.AgentUser, opts.AgentAccessGroup, opts.OperatorUser, opts.OperatorAccessGroup, helperUnit, frontendUnit, sockets)
	return err
}
