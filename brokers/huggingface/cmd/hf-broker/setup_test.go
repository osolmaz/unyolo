//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policypreset"
	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

func TestRunWithArgsVersion(t *testing.T) {
	oldVersion := version
	version = "v1.2.3-test"
	t.Cleanup(func() { version = oldVersion })
	var stdout bytes.Buffer
	err := runWithArgs(context.Background(), nil, &stdout, ioDiscard{}, []string{"--version"})
	if err != nil {
		t.Fatalf("runWithArgs() error = %v", err)
	}
	if got := strings.TrimSpace(stdout.String()); got != "v1.2.3-test" {
		t.Fatalf("version output = %q", got)
	}
}

func TestBrokerBaseURLUsesMatchingLoopbackForWildcard(t *testing.T) {
	for bindAddr, want := range map[string]string{
		"0.0.0.0": "http://127.0.0.1:8080",
		"::":      "http://[::1]:8080",
	} {
		if got := brokerBaseURL(bindAddr, 8080); got != want {
			t.Fatalf("brokerBaseURL(%q) = %q, want %q", bindAddr, got, want)
		}
	}
}

func TestParseSetupSystemdRequiresCoreInputs(t *testing.T) {
	_, err := parseSetupSystemd(ioDiscard{}, nil)
	if err == nil || !strings.Contains(err.Error(), "--hf-token-file") {
		t.Fatalf("parseSetupSystemd() error = %v, want token file requirement", err)
	}
}

func TestParseSetupSystemdGeneratesSecret(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "hf-token")
	if err := os.WriteFile(tokenFile, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts, err := parseSetupSystemd(ioDiscard{}, []string{
		"--hf-token-file", tokenFile,
		"--repo", "osolmaz/scraped-news",
		"--repo-type", "dataset",
	})
	if err != nil {
		t.Fatalf("parseSetupSystemd() error = %v", err)
	}
	if len(opts.SharedSecret) != 64 {
		t.Fatalf("generated secret length = %d, want 64", len(opts.SharedSecret))
	}
	if len(opts.OperatorSecret) != 64 || opts.OperatorName != "onur" || opts.OperatorPort != 8081 {
		t.Fatalf("generated operator configuration = %+v", opts)
	}
}

func TestParseSetupSystemdDefaultsToRequestAllPreset(t *testing.T) {
	opts, err := parseSetupSystemd(ioDiscard{}, []string{"--hf-token-file", "/tmp/hf-token"})
	if err != nil {
		t.Fatalf("parseSetupSystemd() error = %v", err)
	}
	if opts.PolicyPreset != "request-all-agent-operations" || opts.Repo != "" {
		t.Fatalf("default policy selection = %+v", opts)
	}
	if _, err := parseSetupSystemd(ioDiscard{}, []string{"--hf-token-file", "/tmp/hf-token", "--repo", "osolmaz/repo"}); err == nil || !strings.Contains(err.Error(), "must be set together") {
		t.Fatalf("incomplete repo selection error = %v", err)
	}
	if _, err := parseSetupSystemd(ioDiscard{}, []string{"--hf-token-file", "/tmp/hf-token", "--deny-operation", "repo.unknown"}); err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("unknown deny override error = %v", err)
	}
	if _, err := parseSetupSystemd(ioDiscard{}, []string{"--hf-token-file", "/tmp/hf-token", "--reset-denied-operations"}); err == nil || !strings.Contains(err.Error(), "requires --replace-policy") {
		t.Fatalf("unconfirmed deny reset error = %v", err)
	}
	if _, err := parseSetupSystemd(ioDiscard{}, []string{
		"--hf-token-file", "/tmp/hf-token", "--repo", "osolmaz/repo", "--repo-type", "model",
		"--replace-policy", "--reset-denied-operations",
	}); err == nil || !strings.Contains(err.Error(), "requires preset policy mode") {
		t.Fatalf("narrow policy deny reset error = %v", err)
	}
}

func TestParseSetupSystemdRequiresCompleteTelegramConfiguration(t *testing.T) {
	base := []string{"--hf-token-file", "/tmp/hf-token", "--repo", "osolmaz/scraped-news", "--repo-type", "dataset"}
	for _, args := range [][]string{
		append(base, "--telegram-bot-token-file", "/tmp/telegram-token"),
		append(base, "--telegram-chat-id", "123"),
	} {
		if _, err := parseSetupSystemd(ioDiscard{}, args); err == nil || !strings.Contains(err.Error(), "must be set together") {
			t.Fatalf("parseSetupSystemd(%v) error = %v", args, err)
		}
	}
}

func TestParseSetupSystemdReadsSharedSecretFromFileAndStdin(t *testing.T) {
	secret := strings.Repeat("s", 32)
	secretFile := filepath.Join(t.TempDir(), "shared-secret")
	if err := os.WriteFile(secretFile, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := []string{"--hf-token-file", "/tmp/hf-token", "--repo", "osolmaz/scraped-news", "--repo-type", "dataset"}
	fromFile, err := parseSetupSystemdInput(ioDiscard{}, strings.NewReader(""), append(base, "--shared-secret-file", secretFile))
	if err != nil || fromFile.SharedSecret != secret {
		t.Fatalf("file secret = %q, err=%v", fromFile.SharedSecret, err)
	}
	fromStdin, err := parseSetupSystemdInput(ioDiscard{}, strings.NewReader(secret+"\n"), append(base, "--shared-secret-stdin"))
	if err != nil || fromStdin.SharedSecret != secret {
		t.Fatalf("stdin secret = %q, err=%v", fromStdin.SharedSecret, err)
	}
	if _, err := parseSetupSystemd(ioDiscard{}, append(base, "--shared-secret", secret)); err == nil {
		t.Fatal("legacy raw --shared-secret was accepted")
	}
}

func TestParseSetupSystemdRejectsReusedOperatorSecret(t *testing.T) {
	secret := strings.Repeat("s", 32)
	dir := t.TempDir()
	clientFile := filepath.Join(dir, "client-secret")
	operatorFile := filepath.Join(dir, "operator-secret")
	for _, path := range []string{clientFile, operatorFile} {
		if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := parseSetupSystemd(ioDiscard{}, []string{
		"--hf-token-file", "/tmp/hf-token", "--repo", "osolmaz/repo", "--repo-type", "model",
		"--shared-secret-file", clientFile, "--operator-secret-file", operatorFile,
	})
	if err == nil || !strings.Contains(err.Error(), "must differ") || strings.Contains(err.Error(), secret) {
		t.Fatalf("parseSetupSystemd() error = %v", err)
	}
}

func TestParseSetupSystemdRejectsUnsafeOperatorSettings(t *testing.T) {
	base := []string{"--hf-token-file", "/tmp/hf-token", "--repo", "osolmaz/repo", "--repo-type", "model"}
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{name: "empty bind", args: []string{"--operator-bind-addr", ""}, want: "IP address or localhost"},
		{name: "unsafe identity", args: []string{"--operator", "onur=admin"}, want: "invalid --operator"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseSetupSystemd(ioDiscard{}, append(append([]string{}, base...), test.args...))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseSetupSystemd() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseSetupSystemdHelpAndPositionals(t *testing.T) {
	var stderr bytes.Buffer
	err := runSetup(context.Background(), ioDiscard{}, &stderr, []string{"systemd", "-h"})
	if err == nil || !strings.Contains(stderr.String(), "-hf-token-file") {
		t.Fatalf("help stderr = %q, error = %v", stderr.String(), err)
	}
	_, err = parseSetupSystemd(ioDiscard{}, []string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("parseSetupSystemd() positional error = %v", err)
	}
}

func TestRenderSystemdSetupFiles(t *testing.T) {
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker",
			ConfigDir: "/etc/hf-broker", StateDir: "/var/lib/hf-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, AllowNonRoot: true,
		},
		HFTokenFile:  "/tmp/hf-token",
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
		OperatorName: "onur", OperatorSecret: "operator-secret-abcdefghijklmnopqrstuvwxyz",
		OperatorBindAddr: "127.0.0.1", OperatorPort: 8081,
	}
	plan := systemdSetupPlan(opts)
	scopeJSON, err := renderScopeJSON(opts.Repo, opts.RepoType)
	if err != nil {
		t.Fatalf("renderScopeJSON() error = %v", err)
	}
	if _, err := renderScopeJSON("osolmaz/team/scraped-news", opts.RepoType); err == nil {
		t.Fatal("renderScopeJSON() with extra path segment error = nil")
	}
	scopeText := string(scopeJSON)
	for _, want := range []string{
		`"rules"`,
		`"operations"`,
		`"repo.contents.read"`,
		`"git.fetch"`,
		`"git.push.append"`,
		`"type": "dataset"`,
		`"owner": "osolmaz"`,
		`"name": "scraped-news"`,
	} {
		if !strings.Contains(scopeText, want) {
			t.Fatalf("scope json missing %q:\n%s", want, scopeText)
		}
	}
	env := renderEnvFile(plan)
	for _, want := range []string{
		"HF_BROKER_HF_TOKEN_FILE=/etc/hf-broker/hf-token",
		"HF_BROKER_SECRETS_FILE=/etc/hf-broker/secrets",
		"HF_BROKER_SCOPE_FILE=/etc/hf-broker/scope.json",
		"HF_BROKER_STATE_DIR=/var/lib/hf-broker",
		"HF_BROKER_OPERATOR_SECRETS_FILE=/etc/hf-broker/operator-secrets",
		"HF_BROKER_OPERATOR_PORT=8081",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("env file missing %q:\n%s", want, env)
		}
	}
	unit, err := renderSystemdUnit(plan)
	if err != nil {
		t.Fatalf("renderSystemdUnit() error = %v", err)
	}
	for _, want := range []string{
		"User=hf-broker",
		"Group=hf-broker",
		"EnvironmentFile=/etc/hf-broker/env",
		"ExecStart=/usr/local/bin/hf-broker",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q:\n%s", want, unit)
		}
	}
}

func TestSetupSystemdDryRun(t *testing.T) {
	var stdout bytes.Buffer
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker",
			ConfigDir: "/etc/hf-broker", StateDir: "/var/lib/hf-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, DryRun: true,
		},
		HFTokenFile:  "/tmp/hf-token",
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "http://127.0.0.1:8080/datasets/osolmaz/scraped-news") {
		t.Fatalf("dry-run output = %q", stdout.String())
	}
}

func TestPrintSystemdSummaryUsesQuotedBaseURL(t *testing.T) {
	var stdout bytes.Buffer
	printSystemdSummary(&stdout, setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			ClientName: "build agent;echo unsafe", ConfigDir: "/etc/hf-broker", BindAddr: "::1", Port: 8080,
		},
		Repo: "osolmaz/scraped-news", RepoType: "dataset",
	})
	output := stdout.String()
	for _, want := range []string{
		"Broker URL:\n  http://[::1]:8080/datasets/osolmaz/scraped-news",
		"--client 'build agent;echo unsafe'",
		"--url 'http://[::1]:8080'",
		"--secret-file '/etc/hf-broker/secrets'",
		"--home-dir '/home/<user>'",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("summary missing %q:\n%s", want, output)
		}
	}
}

func TestSetupSystemdDryRunValidatesSharedUnit(t *testing.T) {
	err := runSetupSystemd(context.Background(), ioDiscard{}, setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			User: "hf-broker", Group: "hf-broker", ConfigDir: "/etc/hf-broker",
			StateDir: "/", SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/hf-broker", DryRun: true,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "filesystem root") {
		t.Fatalf("unsafe dry-run error = %v", err)
	}
}

func TestSystemdSetupPreflightDoesNotRequireExistingServiceAccount(t *testing.T) {
	plan := systemdSetupPlan(setupSystemdOptions{SystemdOptions: bksetup.SystemdOptions{
		User: "hf-broker-user-does-not-exist", Group: "hf-broker-group-does-not-exist",
		ConfigDir: "/etc/hf-broker", StateDir: "/var/lib/hf-broker",
		SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/hf-broker",
	}})
	if err := validateSystemdSetupPlan(plan); err != nil {
		t.Fatalf("validateSystemdSetupPlan() error = %v", err)
	}
}

func TestRunSetupSystemdDryRunFromArgs(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "hf-token")
	if err := os.WriteFile(tokenFile, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := runSetup(context.Background(), &stdout, ioDiscard{}, []string{
		"systemd",
		"--hf-token-file", tokenFile,
		"--repo", "osolmaz/scraped-news",
		"--repo-type", "dataset",
		"--dry-run",
	})
	if err != nil {
		t.Fatalf("runSetup() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "hf-broker systemd service") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunSetupSystemdWritesFilesWithoutStart(t *testing.T) {
	currentUser, currentGroup := currentUserAndGroup(t)
	dir := t.TempDir()
	runner := &recordingRunner{}
	tokenFile := filepath.Join(dir, "source-token")
	if err := os.WriteFile(tokenFile, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: currentUser.Username, Group: currentGroup.Name,
			ConfigDir: filepath.Join(dir, "etc", "hf-broker"), StateDir: filepath.Join(dir, "var", "lib", "hf-broker"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, AllowNonRoot: true, NoStart: true,
		},
		HFTokenFile:  tokenFile,
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
		OperatorName: "onur", OperatorSecret: "operator-secret-abcdefghijklmnopqrstuvwxyz",
		OperatorBindAddr: "127.0.0.1", OperatorPort: 8081,
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "hf-broker systemd service configured") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "abcdefghijklmnopqrstuvwxyz123456") {
		t.Fatalf("setup stdout leaked broker client secret: %q", stdout.String())
	}
	if got := strings.Join(runner.calls, "\n"); got != "getent group "+currentGroup.Name+"\nid -u "+currentUser.Username {
		t.Fatalf("setup runner calls:\n%s", got)
	}
	assertSetupFile(t, filepath.Join(dir, "etc", "hf-broker", "hf-token"), "hf_xxx\n", 0o600)
	assertSetupFile(t, filepath.Join(dir, "etc", "hf-broker", "secrets"), "agent = abcdefghijklmnopqrstuvwxyz123456\n", 0o600)
	assertSetupFileContains(t, filepath.Join(dir, "etc", "hf-broker", operatorSecretsFileName), "onur = ", 0o600)
	operatorData, err := os.ReadFile(filepath.Join(dir, "etc", "hf-broker", operatorSecretsFileName))
	if err != nil {
		t.Fatal(err)
	}
	operatorSecret := strings.TrimSpace(strings.TrimPrefix(string(operatorData), "onur = "))
	if operatorSecret == "" || strings.Contains(stdout.String(), operatorSecret) {
		t.Fatalf("setup leaked or omitted the operator secret")
	}
	assertSetupFileContains(t, filepath.Join(dir, "etc", "hf-broker", "scope.json"), `"name": "scraped-news"`, 0o644)
	assertSetupFileContains(t, filepath.Join(dir, "etc", "hf-broker", "env"), "HF_BROKER_STATE_DIR=", 0o640)
	assertSetupFileContains(t, filepath.Join(dir, "systemd", unitFileName), "ProtectSystem=strict", 0o644)
}

func TestBrokerkitSystemdInstallPlanKeepsProviderPayloadsTyped(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "source-token")
	if err := os.WriteFile(tokenFile, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker",
			ConfigDir: filepath.Join(dir, "etc", "hf-broker"), StateDir: filepath.Join(dir, "var", "lib", "hf-broker"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, NoStart: true,
		},
		HFTokenFile:  tokenFile,
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
		OperatorName: "onur", OperatorSecret: "operator-secret-abcdefghijklmnopqrstuvwxyz",
		OperatorBindAddr: "127.0.0.1", OperatorPort: 8081,
	}
	plan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatalf("brokerkitSystemdInstallPlan() error = %v", err)
	}
	if plan.UnitName != unitFileName || plan.Unit.EnvironmentFile != filepath.Join(opts.ConfigDir, envFileName) {
		t.Fatalf("brokerkit install unit = %+v", plan.Unit)
	}
	wantOwners := map[string]bkservice.ManagedFileOwner{
		hfTokenFileName: bkservice.ManagedFileOwnerService, secretsFileName: bkservice.ManagedFileOwnerService,
		operatorSecretsFileName: bkservice.ManagedFileOwnerService,
		scopeFileName:           bkservice.ManagedFileOwnerRoot, envFileName: bkservice.ManagedFileOwnerRoot,
	}
	for _, file := range plan.Files {
		if got := file.Owner; got != wantOwners[file.Name] {
			t.Fatalf("managed file %s owner = %q, want %q", file.Name, got, wantOwners[file.Name])
		}
		delete(wantOwners, file.Name)
	}
	if len(wantOwners) != 0 {
		t.Fatalf("missing managed files: %v", wantOwners)
	}
}

func TestBrokerkitSystemdInstallPlanIncludesTelegramTokenFile(t *testing.T) {
	dir := t.TempDir()
	hfToken := filepath.Join(dir, "hf-token-source")
	telegramToken := filepath.Join(dir, "telegram-token-source")
	if err := os.WriteFile(hfToken, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telegramToken, []byte("123:telegram\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker", ConfigDir: filepath.Join(dir, "etc"), StateDir: filepath.Join(dir, "state"), SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/bin/test", ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, NoStart: true},
		HFTokenFile:    hfToken, TelegramBotTokenFile: telegramToken, TelegramChatID: 123,
		Repo: "osolmaz/repo", RepoType: "model", SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
	}
	plan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, file := range plan.Files {
		if file.Name == telegramTokenFileName && file.Owner == bkservice.ManagedFileOwnerService && file.Mode == 0o600 {
			found = true
		}
	}
	if !found || !strings.Contains(renderEnvFile(systemdSetupPlan(opts)), "HF_BROKER_TELEGRAM_BOT_TOKEN_FILE=") {
		t.Fatalf("telegram token was not installed: %+v", plan.Files)
	}
	if len(plan.RemoveFiles) != 2 || plan.ReadyCheck == nil || !managedFileRefNamed(plan.RemoveFiles, policyProfileFileName) || !managedFileRefNamed(plan.RemoveFiles, policyManifestFileName) {
		t.Fatalf("configured Telegram plan retires files: %+v", plan.RemoveFiles)
	}
}

func TestBrokerkitSystemdInstallPlanStartsNarrowPolicyWithTelegram(t *testing.T) {
	dir := t.TempDir()
	hfToken := filepath.Join(dir, "hf-token-source")
	telegramToken := filepath.Join(dir, "telegram-token-source")
	if err := os.WriteFile(hfToken, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telegramToken, []byte("123:telegram\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker",
			ConfigDir: filepath.Join(dir, "etc"), StateDir: filepath.Join(dir, "state"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080,
		},
		HFTokenFile: hfToken, TelegramBotTokenFile: telegramToken, TelegramChatID: 123,
		Repo: "osolmaz/repo", RepoType: "model", SharedSecret: strings.Repeat("s", 32),
		OperatorName: "operator", OperatorSecret: strings.Repeat("o", 32),
		OperatorBindAddr: "127.0.0.1", OperatorPort: 8081,
	}
	plan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatal(err)
	}
	if plan.ReadyCheck == nil {
		t.Fatal("narrow policy retirement has no readiness check")
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("narrow policy with Telegram install plan is invalid: %v", err)
	}
}

func TestBrokerkitSystemdInstallPlanRetiresTelegramTokenWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	hfToken := filepath.Join(dir, "hf-token-source")
	if err := os.WriteFile(hfToken, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker", ConfigDir: filepath.Join(dir, "etc"), StateDir: filepath.Join(dir, "state"), SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/bin/test", ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, NoStart: true},
		HFTokenFile:    hfToken, Repo: "osolmaz/repo", RepoType: "model", SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
	}
	plan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RemoveFiles) != 3 || !managedFileRefNamed(plan.RemoveFiles, telegramTokenFileName) || !managedFileRefNamed(plan.RemoveFiles, policyProfileFileName) || !managedFileRefNamed(plan.RemoveFiles, policyManifestFileName) {
		t.Fatalf("disabled Telegram removals = %+v", plan.RemoveFiles)
	}
	if plan.ReadyCheck == nil {
		t.Fatal("disabled Telegram plan has no readiness check")
	}
	if strings.Contains(renderEnvFile(systemdSetupPlan(opts)), "TELEGRAM") {
		t.Fatal("disabled Telegram remains in the environment")
	}
}

func TestBrokerkitSystemdInstallPlanIncludesPresetArtifacts(t *testing.T) {
	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte("hf_example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker",
			ConfigDir: filepath.Join(dir, "etc"), StateDir: filepath.Join(dir, "state"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, NoStart: true,
		},
		HFTokenFile: tokenPath, PolicyPreset: "request-all-agent-operations",
		DeniedOperations: []string{"repo.delete"}, SharedSecret: strings.Repeat("s", 32),
		OperatorName: "operator", OperatorSecret: strings.Repeat("o", 32),
		OperatorBindAddr: "127.0.0.1", OperatorPort: 8081,
	}
	plan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{scopeFileName, policyProfileFileName, policyManifestFileName} {
		if !managedFileNamed(plan.Files, name) {
			t.Fatalf("preset plan missing %s: %+v", name, plan.Files)
		}
	}
	if managedFileIndex(plan.Files, policyProfileFileName) > managedFileIndex(plan.Files, scopeFileName) ||
		managedFileIndex(plan.Files, policyManifestFileName) > managedFileIndex(plan.Files, scopeFileName) {
		t.Fatalf("runtime scope is not the final policy artifact: %+v", plan.Files)
	}
	if managedFileRefNamed(plan.RemoveFiles, policyProfileFileName) || managedFileRefNamed(plan.RemoveFiles, policyManifestFileName) {
		t.Fatalf("preset plan retires its artifacts: %+v", plan.RemoveFiles)
	}
}

func TestBrokerkitSystemdInstallPlanPreservesInstalledDenies(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "etc")
	writeInstalledPolicy(t, configDir, []string{"repo.delete"}, false)
	tokenPath := writeSetupToken(t, dir)
	opts := presetSetupOptions(dir, configDir, tokenPath)
	opts.DeniedOperations = []string{"repo.create"}
	plan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := policypreset.ParseProfile(managedFileData(t, plan.Files, policyProfileFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(profile.DeniedOperations, []string{"repo.create", "repo.delete"}) {
		t.Fatalf("preserved deny operations = %v", profile.DeniedOperations)
	}

	opts.ResetDeniedOperations = true
	opts.DeniedOperations = nil
	resetPlan, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err != nil {
		t.Fatal(err)
	}
	resetProfile, err := policypreset.ParseProfile(managedFileData(t, resetPlan.Files, policyProfileFileName))
	if err != nil {
		t.Fatal(err)
	}
	if len(resetProfile.DeniedOperations) != 0 {
		t.Fatalf("reset deny operations = %v", resetProfile.DeniedOperations)
	}
}

func TestBrokerkitSystemdInstallPlanRejectsModifiedInstalledPolicy(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "etc")
	writeInstalledPolicy(t, configDir, []string{"repo.delete"}, true)
	opts := presetSetupOptions(dir, configDir, writeSetupToken(t, dir))
	if _, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts)); err == nil || !strings.Contains(err.Error(), "installed policy artifacts are modified") {
		t.Fatalf("modified installed policy error = %v", err)
	}
	opts.ResetDeniedOperations = true
	if _, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts)); err != nil {
		t.Fatalf("explicit deny reset did not recover from modified artifacts: %v", err)
	}
}

func writeInstalledPolicy(t *testing.T, configDir string, denied []string, modifyScope bool) {
	t.Helper()
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	installed, err := policypreset.Render(policypreset.NewProfile([]string{"agent"}, denied))
	if err != nil {
		t.Fatal(err)
	}
	if modifyScope {
		installed.PolicyJSON = append(installed.PolicyJSON, '\n')
	}
	for path, data := range map[string][]byte{
		filepath.Join(configDir, policyProfileFileName):  installed.ProfileJSON,
		filepath.Join(configDir, policyManifestFileName): installed.ManifestJSON,
		filepath.Join(configDir, scopeFileName):          installed.PolicyJSON,
	} {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeSetupToken(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("hf_example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func presetSetupOptions(dir, configDir, tokenPath string) setupSystemdOptions {
	return setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: "hf-broker", Group: "hf-broker", ConfigDir: configDir,
			StateDir: filepath.Join(dir, "state"), SystemdDir: filepath.Join(dir, "systemd"),
			BinaryPath: "/usr/bin/hf-broker", ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, NoStart: true,
		},
		HFTokenFile: tokenPath, PolicyPreset: policypreset.RequestAllAgentOperations,
		ReplacePolicy: true, SharedSecret: strings.Repeat("s", 32),
		OperatorName: "operator", OperatorSecret: strings.Repeat("o", 32),
		OperatorBindAddr: "127.0.0.1", OperatorPort: 8081,
	}
}

func managedFileData(t *testing.T, files []bkservice.ManagedFile, name string) []byte {
	t.Helper()
	for _, file := range files {
		if file.Name == name {
			return file.Data
		}
	}
	t.Fatalf("managed file %s missing", name)
	return nil
}

func TestRequirePolicyReplacement(t *testing.T) {
	dir := t.TempDir()
	plan := systemdSetupPlan(setupSystemdOptions{SystemdOptions: bksetup.SystemdOptions{ConfigDir: dir}})
	if err := requirePolicyReplacement(plan); err != nil {
		t.Fatalf("fresh policy replacement check = %v", err)
	}
	if err := os.WriteFile(plan.scopePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requirePolicyReplacement(plan); err == nil || !strings.Contains(err.Error(), "--replace-policy") {
		t.Fatalf("existing policy replacement check = %v", err)
	}
	plan.opts.ReplacePolicy = true
	if err := requirePolicyReplacement(plan); err != nil {
		t.Fatalf("explicit policy replacement check = %v", err)
	}
}

func managedFileNamed(files []bkservice.ManagedFile, name string) bool {
	for _, file := range files {
		if file.Name == name {
			return true
		}
	}
	return false
}

func managedFileIndex(files []bkservice.ManagedFile, name string) int {
	for index, file := range files {
		if file.Name == name {
			return index
		}
	}
	return -1
}

func managedFileRefNamed(files []bkservice.ManagedFileRef, name string) bool {
	for _, file := range files {
		if file.Name == name {
			return true
		}
	}
	return false
}

func TestBrokerkitSystemdInstallPlanRejectsMissingToken(t *testing.T) {
	dir := t.TempDir()
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			User: "hf-broker", Group: "hf-broker",
			ConfigDir: filepath.Join(dir, "etc", "hf-broker"), StateDir: filepath.Join(dir, "var", "lib", "hf-broker"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/hf-broker",
		},
		HFTokenFile: filepath.Join(dir, "missing"), Repo: "osolmaz/repo", RepoType: "model",
	}
	_, err := brokerkitSystemdInstallPlan(systemdSetupPlan(opts))
	if err == nil || !strings.Contains(err.Error(), "read --hf-token-file") {
		t.Fatalf("brokerkitSystemdInstallPlan() error = %v", err)
	}
}

func TestReadHFTokenFileRejectsEmptyToken(t *testing.T) {
	for name, data := range map[string][]byte{"empty": nil, "whitespace": []byte(" \n\t")} {
		t.Run(name, func(t *testing.T) {
			source := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(source, data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readHFTokenFile(source)
			if err == nil || !strings.Contains(err.Error(), "empty") {
				t.Fatalf("readHFTokenFile() error = %v, want empty", err)
			}
		})
	}
}

func TestReadHFTokenFileRejectsOversizedToken(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "large")
	if err := os.WriteFile(source, []byte(strings.Repeat("x", maxHFTokenBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readHFTokenFile(source)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readHFTokenFile() error = %v, want size limit", err)
	}
}

func assertSetupFile(t *testing.T, path string, want string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test fixture path.
	if err != nil || string(data) != want {
		t.Fatalf("setup file %s = %q, err=%v", path, data, err)
	}
	assertSetupMode(t, path, mode)
}

func assertSetupFileContains(t *testing.T, path string, want string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test fixture path.
	if err != nil || !strings.Contains(string(data), want) {
		t.Fatalf("setup file %s missing %q, body=%q, err=%v", path, want, data, err)
	}
	assertSetupMode(t, path, mode)
}

func assertSetupMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("setup file %s mode = %o, want %o", path, info.Mode().Perm(), mode)
	}
}

func currentUserAndGroup(t *testing.T) (*user.User, *user.Group) {
	t.Helper()
	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	currentGroup, err := user.LookupGroupId(currentUser.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return currentUser, currentGroup
}

type recordingRunner struct {
	calls []string
	fail  map[string]bool
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) error {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if r.fail[call] {
		return os.ErrNotExist
	}
	return nil
}
