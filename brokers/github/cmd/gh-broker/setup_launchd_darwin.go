//go:build darwin

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/credentiallifecycle"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

const (
	ghLaunchdLabel = "dev.brokerkit.github"
	ghLaunchdPlist = ghLaunchdLabel + ".plist"
)

func runSetupLaunchdCommand(ctx context.Context, stdout, stderr io.Writer, stdin io.Reader, args []string) error {
	opts, help, err := parseSetupLaunchd(stderr, stdin, args)
	if err != nil || help {
		return err
	}
	if os.Geteuid() != 0 && !opts.AllowNonRoot && !opts.DryRun {
		return errors.New("setup launchd must run as root; try sudo gh-broker setup launchd")
	}
	opts.Lifecycle, err = credentiallifecycle.New(audit.New(stderr), "gh-broker", "local-operator")
	if err != nil {
		return err
	}
	plan := systemdSetupPlan(opts)
	if opts.DryRun {
		return printLaunchdDryRun(stdout, plan)
	}
	if err := checkGitHubPolicyReplacement(stdout, plan); err != nil {
		return err
	}
	installPlan, err := brokerkitLaunchdInstallPlan(plan)
	if err != nil {
		return err
	}
	if err := bkservice.InstallLaunchd(ctx, installPlan); err != nil {
		return err
	}
	return printLaunchdSummary(stdout, plan)
}

func parseSetupLaunchd(stderr io.Writer, stdin io.Reader, args []string) (setupSystemdOptions, bool, error) {
	defaults := []string{
		"--user", "_gh_broker", "--group", "_gh_broker",
		"--config-dir", "/Library/Application Support/BrokerKit/gh-broker/config",
		"--state-dir", "/Library/Application Support/BrokerKit/gh-broker/state",
		"--systemd-dir", "/Library/LaunchDaemons",
		"--endpoint", "unix:///var/run/brokerkit/github/agent/broker.sock",
		"--operator-endpoint", "unix:///var/run/brokerkit/github/operator/broker.sock",
	}
	return parseSetupSystemdCommand(stderr, stdin, append(defaults, rewriteGHLaunchdFlags(args)...))
}

func rewriteGHLaunchdFlags(args []string) []string {
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

func brokerkitLaunchdInstallPlan(plan systemdPlan) (bkservice.LaunchdInstallPlan, error) {
	base, err := brokerkitSystemdInstallPlan(plan)
	if err != nil {
		return bkservice.LaunchdInstallPlan{}, err
	}
	activation, err := bksetup.BuildLaunchdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint)
	if err != nil {
		return bkservice.LaunchdInstallPlan{}, err
	}
	return bkservice.LaunchdInstallPlan{
		User: plan.opts.User, Group: plan.opts.Group, AdditionalGroups: activation.Groups,
		GroupMembers: activation.GroupMembers, ConfigDir: plan.opts.ConfigDir, StateDir: plan.opts.StateDir,
		LaunchdDir: plan.opts.SystemdDir, PlistName: ghLaunchdPlist,
		Files: withoutGHLaunchdEnvironment(base.Files), RemoveFiles: base.RemoveFiles,
		ReadyCheck: base.ReadyCheck, ReadyTimeout: base.ReadyTimeout, ReadyInterval: base.ReadyInterval,
		Unit: ghLaunchdUnit(plan, activation.Sockets), NoStart: plan.opts.NoStart,
		AllowNonRoot: plan.opts.AllowNonRoot, Runner: plan.opts.CommandRunner, Lifecycle: base.Lifecycle,
	}, nil
}

func withoutGHLaunchdEnvironment(files []bkservice.ManagedFile) []bkservice.ManagedFile {
	result := make([]bkservice.ManagedFile, 0, len(files))
	for _, file := range files {
		if file.Name != ghEnvFileName {
			result = append(result, file)
		}
	}
	return result
}

func ghLaunchdUnit(plan systemdPlan, sockets []bkservice.LaunchdSocket) bkservice.LaunchdUnit {
	return bkservice.LaunchdUnit{
		Label: ghLaunchdLabel, ProgramArguments: []string{plan.opts.BinaryPath},
		UserName: plan.opts.User, GroupName: plan.opts.Group, KeepAlive: true,
		ProcessType: "Background", Environment: ghLaunchdEnvironment(plan), Sockets: sockets,
	}
}

func ghLaunchdEnvironment(plan systemdPlan) map[string]string {
	values := map[string]string{
		"GH_BROKER_DEVELOPMENT": "false", "GH_BROKER_AGENT_ENDPOINT": "activation://agent",
		"GH_BROKER_CLIENT_ID": plan.opts.ClientName, "GH_BROKER_SECRETS_FILE": plan.secretsPath,
		"GH_BROKER_SCOPE_FILE": plan.scopePath, "GH_BROKER_STATE_DIR": plan.opts.StateDir,
		"GH_BROKER_OPERATOR_ID": plan.opts.OperatorID, "GH_BROKER_OPERATOR_SECRETS_FILE": plan.operatorSecretsPath,
		"GH_BROKER_OPERATOR_ENDPOINT": "activation://operator", "GH_BROKER_GITHUB_HTTP_TIMEOUT": "30",
		"GH_BROKER_GITHUB_STREAM_TIMEOUT": "600", "GH_BROKER_MAX_RECEIVE_PACK_BYTES": "26214400",
	}
	if plan.opts.GitEndpoint != "" {
		values["GH_BROKER_GIT_ENDPOINT"] = plan.opts.GitEndpoint
	}
	addGHLaunchdCredentials(values, plan)
	if plan.opts.TelegramBotTokenFile != "" {
		values["GH_BROKER_TELEGRAM_BOT_TOKEN_FILE"] = plan.telegramTokenPath
		values["GH_BROKER_TELEGRAM_CHAT_ID"] = strconv.FormatInt(plan.opts.TelegramChatID, 10)
	}
	return values
}

func addGHLaunchdCredentials(values map[string]string, plan systemdPlan) {
	if plan.opts.DevTokenFallback {
		values["GH_BROKER_GITHUB_TOKEN_FILE"] = plan.tokenPath
		return
	}
	values["GH_BROKER_GITHUB_APP_ID_FILE"] = plan.appIDPath
	values["GH_BROKER_GITHUB_APP_PRIVATE_KEY_FILE"] = plan.appPrivateKeyPath
	values["GH_BROKER_GITHUB_WEBHOOK_SECRET_FILE"] = plan.webhookSecretPath
	if plan.opts.GitHubAppClientIDFile != "" {
		values["GH_BROKER_GITHUB_USER_ID"] = strconv.FormatInt(plan.opts.GitHubUserID, 10)
		values["GH_BROKER_GITHUB_APP_CLIENT_ID_FILE"] = plan.appClientIDPath
		values["GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE"] = plan.appClientSecretPath
	}
}

func printLaunchdDryRun(stdout io.Writer, plan systemdPlan) error {
	activation, err := bksetup.BuildLaunchdActivation(plan.opts.SystemdOptions, plan.opts.OperatorEndpoint)
	if err != nil {
		return err
	}
	body, err := bkservice.RenderLaunchd(ghLaunchdUnit(plan, activation.Sockets))
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Would configure gh-broker LaunchDaemon:\n  user: %s\n  group: %s\n  config: %s\n  state: %s\n  plist: %s\n%s", plan.opts.User, plan.opts.Group, plan.opts.ConfigDir, plan.opts.StateDir, filepath.Join(plan.opts.SystemdDir, ghLaunchdPlist), body)
	if err != nil {
		return err
	}
	return printGitHubPolicyReplacementPreview(stdout, plan)
}

func printLaunchdSummary(stdout io.Writer, plan systemdPlan) error {
	_, err := fmt.Fprintf(stdout, "Installed gh-broker LaunchDaemon %s\nAgent endpoint: %s\nOperator endpoint: %s\n", ghLaunchdLabel, plan.opts.Endpoint, plan.opts.OperatorEndpoint)
	return err
}
