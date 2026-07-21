//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/osolmaz/brokerkit/approval/notifier/telegram"
	bkservice "github.com/osolmaz/brokerkit/internal/host/service"
	bksetup "github.com/osolmaz/brokerkit/internal/host/setup"
	"github.com/osolmaz/brokerkit/internal/validatex"
	"github.com/osolmaz/brokerkit/operator/client"
	"github.com/osolmaz/brokerkit/transport/endpoint"
)

const (
	ingressName       = "brokerkit-telegram"
	ingressConfigDir  = "/etc/brokerkit-telegram"
	ingressStateDir   = "/var/lib/brokerkit-telegram"
	ingressSystemdDir = "/etc/systemd/system"
	ingressUnitName   = "brokerkit-telegram.service"
)

type setupOptions struct {
	User                 string
	Group                string
	ConfigDir            string
	StateDir             string
	SystemdDir           string
	BinaryPath           string
	TelegramBotTokenFile string
	TelegramChatID       int64
	Routes               map[string]setupRoute
	DryRun               bool
	NoStart              bool
	AllowNonRoot         bool
	Runner               bkservice.CommandRunner
}

type setupRoute struct {
	Endpoint    string
	TokenFile   string
	AccessGroup string
}

func defaultSetupOptions() setupOptions {
	return setupOptions{
		User: ingressName, Group: ingressName, ConfigDir: ingressConfigDir,
		StateDir: ingressStateDir, SystemdDir: ingressSystemdDir,
		Routes: map[string]setupRoute{
			telegram.RouteHuggingFace: {Endpoint: "unix:///run/brokerkit/huggingface/operator/broker.sock", AccessGroup: "hf-broker-operator"},
			telegram.RouteGitHub:      {Endpoint: "unix:///run/brokerkit/github/operator/broker.sock", AccessGroup: "gh-broker-operator"},
			telegram.RouteSudo:        {Endpoint: "unix:///run/brokerkit/sudo/operator/broker.sock", AccessGroup: "sudo-broker-operator"},
		},
	}
}

func runSetup(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	setupArgs, err := systemdSetupArgs(args)
	if err != nil {
		return err
	}
	opts, err := parseSetupOptions(setupArgs, stderr)
	if err != nil {
		return err
	}
	plan, err := ingressInstallPlan(opts)
	if err != nil {
		return err
	}
	return applyIngressInstall(ctx, opts, plan, stdout)
}

func systemdSetupArgs(args []string) ([]string, error) {
	if len(args) == 0 || args[0] != "systemd" {
		return nil, errors.New("usage: brokerkit-telegram setup systemd --telegram-bot-token-file <path> --telegram-chat-id <id> [route flags]")
	}
	return args[1:], nil
}

func applyIngressInstall(ctx context.Context, opts setupOptions, plan bkservice.SystemdInstallPlan, stdout io.Writer) error {
	if opts.DryRun {
		return writeIngressDryRun(opts, plan, stdout)
	}
	if runtime.GOOS != "linux" {
		return errors.New("setup systemd is only supported on Linux")
	}
	if os.Geteuid() != 0 && !opts.AllowNonRoot {
		return errors.New("setup systemd must run as root")
	}
	if err := bkservice.InstallSystemd(ctx, plan); err != nil {
		return err
	}
	_, err := fmt.Fprintf(stdout, "Installed %s with routes %s\n", ingressUnitName, strings.Join(configuredRoutes(opts), ","))
	return err
}

func writeIngressDryRun(opts setupOptions, plan bkservice.SystemdInstallPlan, stdout io.Writer) error {
	unit, err := bkservice.RenderSystemd(plan.Unit)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Would install %s with routes %s\n\n%s", ingressUnitName, strings.Join(configuredRoutes(opts), ","), unit)
	return err
}

func parseSetupOptions(args []string, stderr io.Writer) (setupOptions, error) {
	opts := defaultSetupOptions()
	flags := flag.NewFlagSet("brokerkit-telegram setup systemd", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&opts.User, "user", opts.User, "system service user")
	flags.StringVar(&opts.Group, "group", opts.Group, "system service group")
	flags.StringVar(&opts.ConfigDir, "config-dir", opts.ConfigDir, "managed configuration directory")
	flags.StringVar(&opts.StateDir, "state-dir", opts.StateDir, "managed state directory")
	flags.StringVar(&opts.SystemdDir, "systemd-dir", opts.SystemdDir, "systemd unit directory")
	flags.StringVar(&opts.BinaryPath, "binary", opts.BinaryPath, "brokerkit-telegram executable")
	flags.StringVar(&opts.TelegramBotTokenFile, "telegram-bot-token-file", "", "file containing the Telegram bot token")
	flags.Int64Var(&opts.TelegramChatID, "telegram-chat-id", 0, "Telegram operator chat id")
	bindRouteFlags(flags, opts.Routes, telegram.RouteHuggingFace, "hf")
	bindRouteFlags(flags, opts.Routes, telegram.RouteGitHub, "gh")
	bindRouteFlags(flags, opts.Routes, telegram.RouteSudo, "sudo")
	flags.BoolVar(&opts.DryRun, "dry-run", false, "print the service definition without installing")
	flags.BoolVar(&opts.NoStart, "no-start", false, "install without enabling or starting")
	flags.BoolVar(&opts.AllowNonRoot, "allow-non-root", false, "allow setup as the current identity for tests")
	if err := flags.Parse(args); err != nil {
		return setupOptions{}, err
	}
	if flags.NArg() != 0 {
		return setupOptions{}, errors.New("setup systemd does not accept positional arguments")
	}
	resolved, err := resolveBinary(opts.BinaryPath)
	if err != nil {
		return setupOptions{}, err
	}
	opts.BinaryPath = resolved
	if err := validateSetupOptions(opts); err != nil {
		return setupOptions{}, err
	}
	return opts, nil
}

func bindRouteFlags(flags *flag.FlagSet, routes map[string]setupRoute, route, prefix string) {
	bindRouteStringFlag(flags, routes, route, prefix+"-operator-endpoint", prefix+"-broker Operator V1 endpoint",
		func(value *setupRoute, raw string) { value.Endpoint = raw })
	bindRouteStringFlag(flags, routes, route, prefix+"-operator-token-file", prefix+"-broker raw operator token file",
		func(value *setupRoute, raw string) { value.TokenFile = raw })
	bindRouteStringFlag(flags, routes, route, prefix+"-operator-access-group", prefix+"-broker operator socket access group",
		func(value *setupRoute, raw string) { value.AccessGroup = raw })
}

func bindRouteStringFlag(flags *flag.FlagSet, routes map[string]setupRoute, route, name, usage string,
	set func(*setupRoute, string)) {
	flags.Func(name, usage, func(raw string) error {
		value := routes[route]
		set(&value, raw)
		routes[route] = value
		return nil
	})
}

func validateSetupOptions(opts setupOptions) error {
	if opts.TelegramBotTokenFile == "" || opts.TelegramChatID == 0 {
		return errors.New("--telegram-bot-token-file and --telegram-chat-id are required")
	}
	if len(configuredRoutes(opts)) == 0 {
		return errors.New("at least one --*-operator-token-file is required")
	}
	if err := validatex.AccountNames(map[string]string{"user": opts.User, "group": opts.Group}); err != nil {
		return err
	}
	if err := validateSetupRoutes(opts.Routes); err != nil {
		return err
	}
	return validateSetupPaths(opts)
}

func validateSetupRoutes(routes map[string]setupRoute) error {
	for route, value := range routes {
		if value.TokenFile == "" {
			continue
		}
		if err := validatex.AccountNames(map[string]string{"operator access group": value.AccessGroup}); err != nil {
			return fmt.Errorf("route %q: %w", route, err)
		}
		parsed, err := endpoint.Parse(value.Endpoint, endpoint.ParseOptions{})
		if err != nil || parsed.Scheme() == endpoint.SchemeFD {
			return fmt.Errorf("route %q operator endpoint is invalid", route)
		}
	}
	return nil
}

func validateSetupPaths(opts setupOptions) error {
	for name, path := range map[string]string{
		"config-dir": opts.ConfigDir, "state-dir": opts.StateDir, "systemd-dir": opts.SystemdDir, "binary": opts.BinaryPath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s must be absolute and normalized", name)
		}
	}
	return nil
}

func resolveBinary(path string) (string, error) {
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", err
		}
	}
	return filepath.EvalSymlinks(path)
}

func configuredRoutes(opts setupOptions) []string {
	ordered := []string{telegram.RouteHuggingFace, telegram.RouteGitHub, telegram.RouteSudo}
	result := make([]string, 0, len(ordered))
	for _, route := range ordered {
		if opts.Routes[route].TokenFile != "" {
			result = append(result, route)
		}
	}
	return result
}

func ingressInstallPlan(opts setupOptions) (bkservice.SystemdInstallPlan, error) {
	botToken, err := readSecretFile(opts.TelegramBotTokenFile)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, fmt.Errorf("read Telegram bot token: %w", err)
	}
	managedConfig := ingressConfig{
		TelegramBotTokenFile: filepath.Join(opts.ConfigDir, "telegram-bot-token"),
		TelegramChatID:       opts.TelegramChatID,
		InboxPath:            filepath.Join(opts.StateDir, "callbacks.db"),
		InboxKeyFile:         filepath.Join(opts.ConfigDir, "inbox-key"),
		Routes:               map[string]routeConfig{},
	}
	inboxKey, err := existingOrGeneratedInboxKey(filepath.Join(opts.ConfigDir, "inbox-key"), opts.DryRun || opts.AllowNonRoot)
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	files := []bkservice.ManagedFile{
		{Area: bkservice.ManagedFileConfig, Name: "telegram-bot-token", Data: []byte(botToken + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "telegram-bot"},
		{Area: bkservice.ManagedFileConfig, Name: "inbox-key", Data: []byte(inboxKey + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "telegram-inbox"},
		{Area: bkservice.ManagedFileConfig, Name: "env", Data: []byte("# managed by brokerkit-telegram\n"), Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot},
	}
	groups := make([]string, 0, len(opts.Routes))
	readyClients := make([]*operatorclient.Client, 0, len(opts.Routes))
	for _, route := range configuredRoutes(opts) {
		source := opts.Routes[route]
		token, readErr := readSecretFile(source.TokenFile)
		if readErr != nil {
			return bkservice.SystemdInstallPlan{}, fmt.Errorf("read route %q operator token: %w", route, readErr)
		}
		name := "operator-token-" + route
		readyClient, clientErr := operatorclient.New(source.Endpoint, token, nil)
		if clientErr != nil {
			return bkservice.SystemdInstallPlan{}, fmt.Errorf("configure route %q readiness: %w", route, clientErr)
		}
		readyClients = append(readyClients, readyClient)
		files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: name, Data: []byte(token + "\n"), Mode: 0o600, Owner: bkservice.ManagedFileOwnerService, CredentialClass: "broker-operator-" + route})
		managedConfig.Routes[route] = routeConfig{OperatorEndpoint: source.Endpoint, OperatorTokenFile: filepath.Join(opts.ConfigDir, name)}
		groups = append(groups, source.AccessGroup)
	}
	configData, err := json.MarshalIndent(managedConfig, "", "  ")
	if err != nil {
		return bkservice.SystemdInstallPlan{}, err
	}
	configData = append(configData, '\n')
	files = append(files, bkservice.ManagedFile{Area: bkservice.ManagedFileConfig, Name: "config.json", Data: configData, Mode: 0o640, Owner: bkservice.ManagedFileOwnerRoot})
	pathValidation := bkservice.PathValidationStrict
	if opts.DryRun || opts.AllowNonRoot {
		pathValidation = bkservice.PathValidationPreview
	}
	unit := bkservice.SystemdUnit{
		Description: "BrokerKit Telegram approval ingress", User: opts.User, Group: opts.Group,
		SupplementaryGroups: groups,
		EnvironmentFile:     filepath.Join(opts.ConfigDir, "env"),
		ExecStart:           opts.BinaryPath + " serve --config " + filepath.Join(opts.ConfigDir, "config.json"),
		StateDir:            opts.StateDir, ConfigDir: opts.ConfigDir, HomeAccess: bkservice.HomeAccessDeny,
		PathValidation: pathValidation,
	}
	return bkservice.SystemdInstallPlan{
		User: opts.User, Group: opts.Group, AdditionalGroups: groups,
		ConfigDir: opts.ConfigDir, StateDir: opts.StateDir, SystemdDir: opts.SystemdDir,
		UnitName: ingressUnitName, Files: files, RemoveFiles: retiredRouteCredentials(opts), Unit: unit, NoStart: opts.NoStart,
		ReadyCheck:   ingressReadyCheck(readyClients),
		AllowNonRoot: opts.AllowNonRoot, Runner: opts.Runner,
	}, nil
}

func existingOrGeneratedInboxKey(path string, preview bool) (string, error) {
	value, err := readSecretFile(path)
	if err == nil {
		return value, nil
	}
	if !errors.Is(err, os.ErrNotExist) && !preview {
		return "", fmt.Errorf("read existing Telegram inbox key: %w", err)
	}
	return bksetup.GenerateSecret()
}

func ingressReadyCheck(clients []*operatorclient.Client) bkservice.ReadinessCheck {
	return func(ctx context.Context) error {
		for _, client := range clients {
			descriptor, err := client.Discover(ctx)
			if err != nil || descriptor.APIVersion == "" {
				return errors.New("broker operator route is not ready")
			}
		}
		return nil
	}
}

func retiredRouteCredentials(opts setupOptions) []bkservice.ManagedFileRef {
	result := make([]bkservice.ManagedFileRef, 0, len(opts.Routes))
	for _, route := range []string{telegram.RouteHuggingFace, telegram.RouteGitHub, telegram.RouteSudo} {
		if opts.Routes[route].TokenFile == "" {
			result = append(result, bkservice.ManagedFileRef{Area: bkservice.ManagedFileConfig,
				Name: "operator-token-" + route, CredentialClass: "broker-operator-" + route})
		}
	}
	return result
}
