//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/clientconfig"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const maxSetupFileBytes = 16 << 20

type sudoSystemdOptions struct {
	bksetup.SystemdOptions
	PolicyFile           string
	CatalogFile          string
	HelperBinary         string
	HelperStateDir       string
	HelperSocket         string
	SharedSecret         string
	OperatorID           string
	OperatorSecretFile   string
	OperatorSecret       string
	OperatorBindAddr     string
	OperatorPort         int
	TelegramBotTokenFile string
	TelegramChatID       int64
}

type sudoInstallPaths struct {
	policy, catalog, secrets, operators, telegram, frontendEnv, helperEnv string
}

func runSetupSystemd(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer) error {
	opts, help, err := parseSudoSystemdOptions(args, stderr, os.Stdin)
	if err != nil || help {
		return err
	}
	if os.Geteuid() != 0 && !opts.DryRun {
		return errors.New("setup systemd must run as root; try sudo sudo-broker setup systemd")
	}
	paths := sudoPaths(opts)
	helperPlan, frontendPlan, err := sudoInstallPlans(opts, paths)
	if err != nil {
		return err
	}
	if opts.DryRun {
		return printSudoSystemdPlan(stdout, opts, paths, helperPlan, frontendPlan)
	}
	if err := bkservice.InstallSystemd(ctx, helperPlan); err != nil {
		return fmt.Errorf("install privileged helper: %w", err)
	}
	if err := bkservice.InstallSystemd(ctx, frontendPlan); err != nil {
		return fmt.Errorf("install unprivileged frontend: %w", err)
	}
	_, err = fmt.Fprintf(stdout, "sudo-broker installed\n  broker: http://%s\n  operator: http://%s\n  helper socket: %s\n  client secrets: %s\n",
		net.JoinHostPort(opts.BindAddr, strconv.Itoa(opts.Port)), net.JoinHostPort(opts.OperatorBindAddr, strconv.Itoa(opts.OperatorPort)), opts.HelperSocket, paths.secrets)
	return err
}

func parseSudoSystemdOptions(args []string, stderr io.Writer, stdin io.Reader) (sudoSystemdOptions, bool, error) {
	common := bksetup.DefaultSystemdOptions(bksetup.SystemdDefaults{
		BrokerName: "sudo-broker", User: "sudo-broker", Group: "sudo-broker", ClientName: "bob", BindAddr: "127.0.0.1", Port: 8084,
	})
	common.StateDir = "/var/lib/sudo-broker/frontend"
	opts := sudoSystemdOptions{SystemdOptions: common, HelperStateDir: "/var/lib/sudo-broker/helper",
		HelperSocket: "/run/sudo-broker/helper.sock", OperatorID: "onur", OperatorBindAddr: "127.0.0.1", OperatorPort: 8085}
	var output strings.Builder
	flags := flag.NewFlagSet("sudo-broker setup systemd", flag.ContinueOnError)
	flags.SetOutput(&output)
	bksetup.BindSystemdFlags(flags, &opts.SystemdOptions)
	flags.StringVar(&opts.PolicyFile, "policy-file", "", "sudo policy JSON source")
	flags.StringVar(&opts.CatalogFile, "catalog-file", "", "root-reviewed command catalog source")
	flags.StringVar(&opts.HelperBinary, "helper-binary", "", "sudo-broker-exec binary path")
	flags.StringVar(&opts.HelperStateDir, "helper-state-dir", opts.HelperStateDir, "root-owned helper state directory")
	flags.StringVar(&opts.HelperSocket, "helper-socket", opts.HelperSocket, "frontend-to-helper Unix socket")
	flags.StringVar(&opts.OperatorID, "operator", opts.OperatorID, "operator identity")
	flags.StringVar(&opts.OperatorSecretFile, "operator-secret-file", "", "operator secret source")
	flags.StringVar(&opts.OperatorBindAddr, "operator-bind-addr", opts.OperatorBindAddr, "operator listen address")
	flags.IntVar(&opts.OperatorPort, "operator-port", opts.OperatorPort, "operator listen port")
	flags.StringVar(&opts.TelegramBotTokenFile, "telegram-bot-token-file", "", "Telegram bot token source")
	flags.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram approval chat id")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.Copy(stderr, strings.NewReader(output.String()))
			return sudoSystemdOptions{}, true, nil
		}
		return sudoSystemdOptions{}, false, errors.New("invalid setup systemd flags")
	}
	if flags.NArg() != 0 {
		return sudoSystemdOptions{}, false, errors.New("setup systemd does not accept positional arguments")
	}
	finalized, err := bksetup.FinalizeSystemd(opts.SystemdOptions)
	if err != nil {
		return sudoSystemdOptions{}, false, err
	}
	opts.SystemdOptions = finalized
	if opts.HelperBinary == "" {
		opts.HelperBinary = defaultHelperBinary(opts.BinaryPath)
	}
	resolvedHelper, err := filepath.EvalSymlinks(opts.HelperBinary)
	if err != nil {
		return sudoSystemdOptions{}, false, fmt.Errorf("resolve helper binary: %w", err)
	}
	opts.HelperBinary = resolvedHelper
	opts.SharedSecret, err = bksetup.ResolveSecret(bksetup.SecretInput{File: opts.SharedSecretFile, Stdin: opts.SharedSecretStdin}, stdin)
	if err != nil {
		return sudoSystemdOptions{}, false, err
	}
	opts.OperatorSecret, err = bksetup.ResolveSecret(bksetup.SecretInput{File: opts.OperatorSecretFile}, strings.NewReader(""))
	if err != nil {
		return sudoSystemdOptions{}, false, err
	}
	return opts, false, validateSudoSystemdOptions(opts)
}

func defaultHelperBinary(frontend string) string {
	beside := filepath.Join(filepath.Dir(frontend), "sudo-broker-exec")
	if info, err := os.Stat(beside); err == nil && info.Mode().IsRegular() {
		return beside
	}
	return "/usr/local/libexec/sudo-broker-exec"
}

func validateSudoSystemdOptions(opts sudoSystemdOptions) error {
	if opts.PolicyFile == "" || opts.CatalogFile == "" {
		return errors.New("--policy-file and --catalog-file are required")
	}
	if opts.AllowNonRoot && !opts.DryRun {
		return errors.New("sudo-broker systemd setup does not support non-root installation")
	}
	for name, value := range map[string]string{"helper binary": opts.HelperBinary, "helper state": opts.HelperStateDir, "helper socket": opts.HelperSocket} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute normalized path", name)
		}
	}
	if opts.HelperStateDir == opts.StateDir || opts.OperatorPort == opts.Port || opts.OperatorPort < 1 || opts.OperatorPort > 65535 {
		return errors.New("helper/frontend state and agent/operator ports must differ")
	}
	if err := validateLoopbackAddress(net.JoinHostPort(opts.OperatorBindAddr, strconv.Itoa(opts.OperatorPort))); err != nil {
		return fmt.Errorf("operator listener: %w", err)
	}
	if err := clientconfig.ValidateClientName(opts.OperatorID); err != nil {
		return err
	}
	if opts.OperatorSecret == opts.SharedSecret {
		return errors.New("operator secret must differ from the client secret")
	}
	if (opts.TelegramBotTokenFile == "") != (opts.TelegramChatID == 0) {
		return errors.New("--telegram-bot-token-file and --telegram-chat-id must be configured together")
	}
	if os.Geteuid() == 0 && !opts.DryRun {
		if err := hostcheck.ValidateRootFile(opts.HelperBinary); err != nil {
			return fmt.Errorf("helper binary is not trusted: %w", err)
		}
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

func sudoInstallPlans(opts sudoSystemdOptions, paths sudoInstallPaths) (bkservice.SystemdInstallPlan, bkservice.SystemdInstallPlan, error) {
	snapshot, err := catalog.Load(opts.CatalogFile)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, bkservice.SystemdInstallPlan{}, err
	}
	if _, err := bkpolicy.LoadFile(opts.PolicyFile, sudopolicy.Registry(snapshot)); err != nil {
		return bkservice.SystemdInstallPlan{}, bkservice.SystemdInstallPlan{}, err
	}
	catalogData, err := readSetupFile(opts.CatalogFile)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, bkservice.SystemdInstallPlan{}, err
	}
	policyData, err := readSetupFile(opts.PolicyFile)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, bkservice.SystemdInstallPlan{}, err
	}
	pathValidation := bkservice.PathValidationStrict
	if opts.DryRun {
		pathValidation = bkservice.PathValidationPreview
	}
	helperUnit := bkservice.SystemdUnit{Description: "sudo-broker privileged command executor", User: "root", Group: opts.Group,
		EnvironmentFile: paths.helperEnv, ExecStart: strings.Join([]string{opts.HelperBinary, "--catalog", paths.catalog, "--state", filepath.Join(opts.HelperStateDir, "executions.json"), "--socket", opts.HelperSocket, "--broker-user", opts.User}, " "),
		StateDir: opts.HelperStateDir, ConfigDir: opts.ConfigDir, PrivilegeEscalation: bkservice.PrivilegeEscalationAllow,
		PathValidation: pathValidation, RuntimeDirectory: "sudo-broker", RuntimeDirectoryMode: 0o750,
		ExtraDirectives: hardeningDirectives(false)}
	frontendUnit := bkservice.SystemdUnit{Description: "sudo-broker approval frontend", User: opts.User, Group: opts.Group,
		EnvironmentFile: paths.frontendEnv, ExecStart: frontendExec(opts, paths), StateDir: opts.StateDir, ConfigDir: opts.ConfigDir,
		PathValidation: pathValidation, AfterUnits: []string{"sudo-broker-exec.service"}, RequiresUnits: []string{"sudo-broker-exec.service"},
		ExtraDirectives: hardeningDirectives(true)}
	sharedStateDir := sharedStateDirectory(opts.StateDir, opts.HelperStateDir)
	helperPlan := bkservice.SystemdInstallPlan{User: "root", Group: opts.Group, ConfigDir: opts.ConfigDir, StateDir: opts.HelperStateDir, SharedStateDir: sharedStateDir,
		SystemdDir: opts.SystemdDir, UnitName: "sudo-broker-exec.service", NoStart: true, Unit: helperUnit,
		Files: []bkservice.ManagedFile{
			{Area: bkservice.ManagedFileConfig, Name: "catalog.json", Data: catalogData, Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
			{Area: bkservice.ManagedFileConfig, Name: "helper.env", Data: []byte("# managed by sudo-broker\n"), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
		}}
	frontendFiles := []bkservice.ManagedFile{
		{Area: bkservice.ManagedFileConfig, Name: "policy.json", Data: policyData, Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
		frontendSecretFile("secrets", []byte(opts.ClientName+" = "+opts.SharedSecret+"\n")),
		frontendSecretFile("operator-secrets", []byte(opts.OperatorID+" = "+opts.OperatorSecret+"\n")),
		{Area: bkservice.ManagedFileConfig, Name: "frontend.env", Data: []byte("# managed by sudo-broker\n"), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
	}
	if opts.TelegramBotTokenFile != "" {
		data, readErr := readSetupFile(opts.TelegramBotTokenFile)
		if readErr != nil {
			return bkservice.SystemdInstallPlan{}, bkservice.SystemdInstallPlan{}, readErr
		}
		frontendFiles = append(frontendFiles, frontendSecretFile("telegram-bot-token", data))
	}
	frontendPlan := bkservice.SystemdInstallPlan{User: opts.User, Group: opts.Group, ConfigDir: opts.ConfigDir, StateDir: opts.StateDir, SharedStateDir: sharedStateDir,
		SystemdDir: opts.SystemdDir, UnitName: "sudo-broker.service", NoStart: opts.NoStart, Unit: frontendUnit, Files: frontendFiles,
		ReadyCheck: bkservice.HTTPReadyCheck("http://"+net.JoinHostPort(opts.BindAddr, strconv.Itoa(opts.Port))+"/readyz", localHTTPClient())}
	return helperPlan, frontendPlan, nil
}

func sharedStateDirectory(frontend string, helper string) string {
	parent := filepath.Dir(frontend)
	if parent != filepath.Dir(helper) || strings.Count(strings.Trim(parent, string(filepath.Separator)), string(filepath.Separator)) < 2 {
		return ""
	}
	return parent
}

func frontendSecretFile(name string, data []byte) bkservice.ManagedFile {
	return bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: name, Data: data, Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot}
}

func frontendExec(opts sudoSystemdOptions, paths sudoInstallPaths) string {
	values := []string{opts.BinaryPath, "serve", "--policy", paths.policy, "--catalog", paths.catalog, "--secrets", paths.secrets,
		"--operator-secrets", paths.operators, "--state", opts.StateDir,
		"--helper-socket", opts.HelperSocket, "--bind", net.JoinHostPort(opts.BindAddr, strconv.Itoa(opts.Port)),
		"--operator-bind", net.JoinHostPort(opts.OperatorBindAddr, strconv.Itoa(opts.OperatorPort))}
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

func localHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport}
}

func printSudoSystemdPlan(stdout io.Writer, opts sudoSystemdOptions, paths sudoInstallPaths, helper bkservice.SystemdInstallPlan, frontend bkservice.SystemdInstallPlan) error {
	helperUnit, err := bkservice.RenderSystemd(helper.Unit)
	if err != nil {
		return err
	}
	frontendUnit, err := bkservice.RenderSystemd(frontend.Unit)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Would install sudo-broker\n  frontend user: %s\n  frontend state: %s\n  helper user: root\n  helper state: %s\n  helper socket: %s\n  policy: %s\n  catalog: %s\n\n%s\n%s", opts.User, opts.StateDir, opts.HelperStateDir, opts.HelperSocket, paths.policy, paths.catalog, helperUnit, frontendUnit)
	return err
}
