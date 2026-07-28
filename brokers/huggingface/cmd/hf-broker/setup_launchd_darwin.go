//go:build darwin

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/osolmaz/unyolo/credential/lifecycle"
	unyoloservice "github.com/osolmaz/unyolo/internal/host/service"
	unyolosetup "github.com/osolmaz/unyolo/internal/host/setup"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

const (
	hfLaunchdLabel = "io.unyolo.huggingface"
	hfLaunchdPlist = hfLaunchdLabel + ".plist"
)

func runSetupLaunchdCommand(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer, args []string) error {
	opts, err := parseSetupLaunchd(stderr, stdin, args)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 && !opts.AllowNonRoot && !opts.DryRun {
		return exitError{code: 1, message: "setup launchd must run as root; try sudo hf-broker setup launchd ..."}
	}
	opts.Lifecycle, err = credentiallifecycle.New(audit.New(stderr), "hf-broker", "local-operator")
	if err != nil {
		return err
	}
	plan := systemdSetupPlan(opts)
	if opts.DryRun {
		return printLaunchdDryRun(stdout, plan)
	}
	if err := checkPolicyReplacement(stdout, plan); err != nil {
		return err
	}
	installPlan, err := unyoloLaunchdInstallPlan(plan)
	if err != nil {
		return exitError{code: 64, message: err.Error()}
	}
	if err := unyoloservice.InstallLaunchd(ctx, installPlan); err != nil {
		return err
	}
	return printLaunchdSummary(stdout, opts)
}

func parseSetupLaunchd(stderr io.Writer, stdin io.Reader, args []string) (setupSystemdOptions, error) {
	defaults := []string{
		"--user", "_hf_broker", "--group", "_hf_broker",
		"--config-dir", "/Library/Application Support/unyolo/hf-broker/config",
		"--state-dir", "/Library/Application Support/unyolo/hf-broker/state",
		"--systemd-dir", "/Library/LaunchDaemons",
		"--endpoint", "unix:///var/run/unyolo/huggingface/agent/broker.sock",
		"--operator-endpoint", "unix:///var/run/unyolo/huggingface/operator/broker.sock",
	}
	return parseSetupSystemdInput(stderr, stdin, append(defaults, rewriteLaunchdFlags(args)...))
}

func rewriteLaunchdFlags(args []string) []string {
	result := append([]string(nil), args...)
	for index, argument := range result {
		if argument == "--launchd-dir" {
			result[index] = "--systemd-dir"
		} else if strings.HasPrefix(argument, "--launchd-dir=") {
			result[index] = "--systemd-dir=" + strings.TrimPrefix(argument, "--launchd-dir=")
		}
	}
	return result
}

func unyoloLaunchdInstallPlan(plan systemdPlan) (unyoloservice.LaunchdInstallPlan, error) {
	base, err := unyoloSystemdInstallPlan(plan)
	if err != nil {
		return unyoloservice.LaunchdInstallPlan{}, err
	}
	activation, err := unyolosetup.BuildLaunchdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint)
	if err != nil {
		return unyoloservice.LaunchdInstallPlan{}, err
	}
	return unyoloservice.LaunchdInstallPlan{
		User: plan.opts.User, Group: plan.opts.Group, AdditionalGroups: activation.Groups,
		GroupMembers: activation.GroupMembers, ConfigDir: plan.opts.ConfigDir, StateDir: plan.opts.StateDir,
		LaunchdDir: plan.opts.SystemdDir, PlistName: hfLaunchdPlist,
		Files: withoutLaunchdEnvironmentFile(base.Files), RemoveFiles: base.RemoveFiles,
		ReadyCheck: base.ReadyCheck, ReadyTimeout: base.ReadyTimeout, ReadyInterval: base.ReadyInterval,
		Unit: hfLaunchdUnit(plan, activation.Sockets), NoStart: plan.opts.NoStart,
		AllowNonRoot: plan.opts.AllowNonRoot, Runner: plan.opts.CommandRunner, Lifecycle: base.Lifecycle,
	}, nil
}

func withoutLaunchdEnvironmentFile(files []unyoloservice.ManagedFile) []unyoloservice.ManagedFile {
	result := make([]unyoloservice.ManagedFile, 0, len(files))
	for _, file := range files {
		if file.Name != envFileName {
			result = append(result, file)
		}
	}
	return result
}

func hfLaunchdUnit(plan systemdPlan, sockets []unyoloservice.LaunchdSocket) unyoloservice.LaunchdUnit {
	return unyoloservice.LaunchdUnit{
		Label: hfLaunchdLabel, ProgramArguments: []string{plan.opts.BinaryPath},
		UserName: plan.opts.User, GroupName: plan.opts.Group, KeepAlive: true,
		ProcessType: "Background", Environment: hfLaunchdEnvironment(plan), Sockets: sockets,
	}
}

func hfLaunchdEnvironment(plan systemdPlan) map[string]string {
	values := map[string]string{
		"HF_BROKER_HF_TOKEN_FILE": plan.tokenPath, "HF_BROKER_SECRETS_FILE": plan.secretsPath,
		"HF_BROKER_SCOPE_FILE": plan.scopePath, "HF_BROKER_STATE_DIR": plan.opts.StateDir,
		"HF_BROKER_XET_PYTHON":            plan.opts.XetPython,
		"HF_BROKER_AGENT_ENDPOINT":        "activation://agent",
		"HF_BROKER_OPERATOR_SECRETS_FILE": plan.operatorSecretsPath,
		"HF_BROKER_OPERATOR_ENDPOINT":     "activation://operator",
	}
	if plan.opts.GitEndpoint != "" {
		values["HF_BROKER_GIT_ENDPOINT"] = plan.opts.GitEndpoint
	}
	if plan.opts.TelegramBotTokenFile != "" {
		values["HF_BROKER_TELEGRAM_BOT_TOKEN_FILE"] = plan.telegramTokenPath
		values["HF_BROKER_TELEGRAM_CHAT_ID"] = strconv.FormatInt(plan.opts.TelegramChatID, 10)
	}
	return values
}

func printLaunchdDryRun(stdout io.Writer, plan systemdPlan) error {
	activation, err := unyolosetup.BuildLaunchdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint)
	if err != nil {
		return err
	}
	body, err := unyoloservice.RenderLaunchd(hfLaunchdUnit(plan, activation.Sockets))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Would configure hf-broker LaunchDaemon:\n  user: %s\n  group: %s\n  config: %s\n  state: %s\n  plist: %s\n%s", plan.opts.User, plan.opts.Group, plan.opts.ConfigDir, plan.opts.StateDir, filepath.Join(plan.opts.SystemdDir, hfLaunchdPlist), body)
	if err != nil {
		return err
	}
	return printPolicyReplacementPreview(stdout, plan)
}

func printLaunchdSummary(stdout io.Writer, opts setupSystemdOptions) error {
	_, err := fmt.Fprintf(stdout, "Installed hf-broker LaunchDaemon %s\nAgent endpoint: %s\nOperator endpoint: %s\n", hfLaunchdLabel, opts.Endpoint, opts.OperatorEndpoint)
	return err
}
