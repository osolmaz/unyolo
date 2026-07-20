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

	"github.com/osolmaz/brokerkit/brokers/github/internal/policypreset"
	bkservice "github.com/osolmaz/brokerkit/internal/host/service"
	bksetup "github.com/osolmaz/brokerkit/internal/host/setup"
)

const (
	testGHAgentEndpoint    = "unix:///run/brokerkit/github/agent/broker.sock"
	testGHOperatorEndpoint = "unix:///run/brokerkit/github/operator/broker.sock"
)

func requiredGHSetupArgs(args ...string) []string {
	return append([]string{"--client", "agent-a", "--operator", "operator-a", "--agent-user", "agent-user", "--operator-user", "operator-user"}, args...)
}

func TestParseSetupSystemdDefaultsToManagedPreset(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeFixture(t, dir, "github-token", "ghp_token\n")
	opts, err := parseSetupSystemd(ioDiscard{}, strings.NewReader(""), requiredGHSetupArgs("--github-token-file", tokenFile, "--dev-token-fallback"))
	if err != nil {
		t.Fatalf("parseSetupSystemd() error = %v", err)
	}
	if opts.ScopeFile != "" || opts.PolicyPreset != policypreset.RequestAllAgentOperations {
		t.Fatalf("policy options = %+v", opts)
	}
}

func TestRunSetupSystemdCommandHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runSetupSystemdCommand(context.Background(), &stdout, &stderr, strings.NewReader(""), []string{"--help"})
	if err != nil {
		t.Fatalf("runSetupSystemdCommand(help) error = %v", err)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "gh-broker setup systemd") {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestParseSetupSystemdGeneratesSecret(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeFixture(t, dir, "github-token", "ghp_token\n")
	scopeFile := writeFixture(t, dir, "scope.json", minimalScopeJSON())
	opts, err := parseSetupSystemd(ioDiscard{}, strings.NewReader(""), requiredGHSetupArgs(
		"--scope-file", scopeFile,
		"--github-token-file", tokenFile,
		"--dev-token-fallback",
	))
	if err != nil {
		t.Fatalf("parseSetupSystemd() error = %v", err)
	}
	if len(opts.SharedSecret) != 64 {
		t.Fatalf("generated secret length = %d, want 64", len(opts.SharedSecret))
	}
	if len(opts.OperatorSecret) != 64 || opts.OperatorID != "operator-a" || opts.OperatorEndpoint != testGHOperatorEndpoint {
		t.Fatalf("generated operator config = %+v", opts)
	}
}

func TestParseSetupSystemdReadsSharedSecretFromFileAndStdin(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeFixture(t, dir, "github-token", "ghp_token\n")
	scopeFile := writeFixture(t, dir, "scope.json", minimalScopeJSON())
	secretFile := writeFixture(t, dir, "client-secret", strings.Repeat("s", 32)+"\n")
	opts, err := parseSetupSystemd(ioDiscard{}, strings.NewReader(""), requiredGHSetupArgs(
		"--scope-file", scopeFile,
		"--github-token-file", tokenFile,
		"--dev-token-fallback",
		"--shared-secret-file", secretFile,
	))
	if err != nil {
		t.Fatalf("parseSetupSystemd(file) error = %v", err)
	}
	if opts.SharedSecret != strings.Repeat("s", 32) {
		t.Fatalf("SharedSecret from file = %q", opts.SharedSecret)
	}
	opts, err = parseSetupSystemd(ioDiscard{}, strings.NewReader(strings.Repeat("t", 32)+"\n"), requiredGHSetupArgs(
		"--scope-file", scopeFile,
		"--github-token-file", tokenFile,
		"--dev-token-fallback",
		"--shared-secret-stdin",
	))
	if err != nil {
		t.Fatalf("parseSetupSystemd(stdin) error = %v", err)
	}
	if opts.SharedSecret != strings.Repeat("t", 32) {
		t.Fatalf("SharedSecret from stdin = %q", opts.SharedSecret)
	}
}

func TestSetupSystemdDryRunForDevTokenFallback(t *testing.T) {
	var stdout bytes.Buffer
	configDir := t.TempDir()
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{ // #nosec G101 -- test fixture paths and generated secrets are not credentials.
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ConfigDir: configDir, StateDir: "/var/lib/gh-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/gh-broker",
			ClientName: "agent-a", Endpoint: testGHAgentEndpoint, DryRun: true,
		},
		GitHubTokenFile: "/tmp/github-token",
		PolicyPreset:    policypreset.RequestAllAgentOperations,
		SharedSecret:    strings.Repeat("s", 32),
		OperatorID:      "operator-a", OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: testGHOperatorEndpoint,
		DevTokenFallback: true,
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	for _, want := range []string{
		"gh-broker systemd service",
		"token fallback:  true",
		"github token:    " + filepath.Join(configDir, githubTokenFileName),
		"broker endpoint: " + testGHAgentEndpoint,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry-run missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestSetupSystemdDryRunValidatesInstallPlan(t *testing.T) {
	var stdout bytes.Buffer
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{ // #nosec G101 -- generated test secrets are not credentials.
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ConfigDir: t.TempDir(), StateDir: "/var/lib/gh-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "relative/gh-broker",
			ClientName: "agent-a", Endpoint: testGHAgentEndpoint, DryRun: true,
		},
		GitHubTokenFile: "/tmp/github-token", PolicyPreset: policypreset.RequestAllAgentOperations,
		SharedSecret: strings.Repeat("s", 32), OperatorID: "operator-a",
		OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: testGHOperatorEndpoint,
		DevTokenFallback: true,
	})
	if err == nil {
		t.Fatal("dry-run accepted an invalid systemd install plan")
	}
}

func TestSetupSystemdDryRunForGitHubAppFiles(t *testing.T) {
	var stdout bytes.Buffer
	configDir := t.TempDir()
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{ // #nosec G101 -- test fixture paths and generated secrets are not credentials.
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ConfigDir: configDir, StateDir: "/var/lib/gh-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/gh-broker",
			ClientName: "agent-a", Endpoint: testGHAgentEndpoint, DryRun: true,
		},
		GitHubAppIDFile:         "/tmp/app-id",
		GitHubAppPrivateKeyFile: "/tmp/private-key.pem",
		GitHubWebhookSecretFile: "/tmp/webhook-secret",
		PolicyPreset:            policypreset.RequestAllAgentOperations,
		SharedSecret:            strings.Repeat("s", 32),
		OperatorID:              "operator-a", OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: testGHOperatorEndpoint,
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	for _, want := range []string{
		"token fallback:  false",
		"app id file:     " + filepath.Join(configDir, githubAppIDFileName),
		"app private key: " + filepath.Join(configDir, githubAppPrivateKeyFileName),
		"broker endpoint: " + testGHAgentEndpoint,
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry-run missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestRunSetupSystemdWritesFilesWithoutStart(t *testing.T) {
	currentUser, currentGroup := currentUserAndGroup(t)
	dir := t.TempDir()
	tokenFile := writeFixture(t, dir, "source-token", "ghp_token\n")
	telegramTokenFile := writeFixture(t, dir, "telegram-token", "123:telegram-secret\n")
	scopeFile := writeFixture(t, dir, "scope.json", minimalScopeJSON())
	var stdout bytes.Buffer
	runner := &recordingRunner{}
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: currentUser.Username, Group: currentGroup.Name,
			ConfigDir: filepath.Join(dir, "etc", "gh-broker"), StateDir: filepath.Join(dir, "var", "lib", "gh-broker"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/gh-broker",
			ClientName: "agent-a", Endpoint: testGHAgentEndpoint, AllowNonRoot: true, NoStart: true,
		},
		GitHubTokenFile:      tokenFile,
		ScopeFile:            scopeFile,
		SharedSecret:         strings.Repeat("s", 32),
		OperatorID:           "operator-a",
		OperatorSecret:       strings.Repeat("o", 32),
		OperatorEndpoint:     testGHOperatorEndpoint,
		TelegramBotTokenFile: telegramTokenFile,
		TelegramChatID:       123,
		DevTokenFallback:     true,
		CommandRunner:        runner,
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "gh-broker systemd service configured") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	wantCalls := "getent group " + currentGroup.Name + "\nid -u " + currentUser.Username +
		"\ngetent group gh-broker-agent\nid -u " + currentUser.Username + "\nusermod --append --groups gh-broker-agent " + currentUser.Username +
		"\ngetent group gh-broker-operator\nid -u " + currentUser.Username + "\nusermod --append --groups gh-broker-operator " + currentUser.Username
	if got := strings.Join(runner.calls, "\n"); got != wantCalls {
		t.Fatalf("setup runner calls:\n%s", got)
	}
	for _, path := range []string{
		filepath.Join(dir, "etc", "gh-broker", "github-token"),
		filepath.Join(dir, "etc", "gh-broker", "secrets"),
		filepath.Join(dir, "etc", "gh-broker", "operator-secrets"),
		filepath.Join(dir, "etc", "gh-broker", "telegram-bot-token"),
		filepath.Join(dir, "etc", "gh-broker", "scope.json"),
		filepath.Join(dir, "etc", "gh-broker", "env"),
		filepath.Join(dir, "systemd", "gh-broker.service"),
		filepath.Join(dir, "systemd", "gh-broker-agent.socket"),
		filepath.Join(dir, "systemd", "gh-broker-operator.socket"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
	envData, err := os.ReadFile(filepath.Join(dir, "etc", "gh-broker", "env")) // #nosec G304 -- test reads its own temp fixture.
	if err != nil {
		t.Fatal(err)
	}
	envText := string(envData)
	for _, want := range []string{
		"GH_BROKER_SECRETS_FILE=",
		"GH_BROKER_GITHUB_TOKEN_FILE=",
		"GH_BROKER_STATE_DIR=",
		"GH_BROKER_OPERATOR_SECRETS_FILE=",
		"GH_BROKER_AGENT_ENDPOINT=activation://agent",
		"GH_BROKER_OPERATOR_ENDPOINT=activation://operator",
		"GH_BROKER_TELEGRAM_BOT_TOKEN_FILE=",
		"GH_BROKER_TELEGRAM_CHAT_ID=123",
	} {
		if !strings.Contains(envText, want) {
			t.Fatalf("env missing %q:\n%s", want, envText)
		}
	}
	assertTextExcludes(t, envText, strings.Repeat("s", 32))
	assertTextExcludes(t, envText, "123:telegram-secret")
}

func TestManagedPresetArtifactsPreserveInstalledDenies(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := systemdSetupPlan(setupSystemdOptions{
		SystemdOptions:   bksetup.SystemdOptions{ConfigDir: configDir, ClientName: "agent-a"},
		PolicyPreset:     policypreset.RequestAllAgentOperations,
		DeniedOperations: bksetup.StringListFlag{"repo.delete"},
	})
	first, err := renderGitHubSetupPolicy(plan)
	if err != nil {
		t.Fatal(err)
	}
	if !first.managedPreset || first.counts == nil || first.counts.Deny != 312 || first.counts.Request != 513 {
		t.Fatalf("first policy = %+v", first)
	}
	for path, data := range map[string][]byte{
		plan.scopePath: first.scope, plan.policyProfilePath: first.profile, plan.policyManifestPath: first.manifest,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plan.opts.DeniedOperations = bksetup.StringListFlag{"pull_request.create"}
	second, err := renderGitHubSetupPolicy(plan)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := policypreset.ParseProfile(second.profile)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"pull_request.create", "repo.delete"}
	if !slices.Equal(profile.DeniedOperations, want) {
		t.Fatalf("preserved denies = %v, want %v", profile.DeniedOperations, want)
	}
	digest, counts, err := currentGitHubPolicyPreview(plan)
	if err != nil {
		t.Fatalf("currentGitHubPolicyPreview() error = %v", err)
	}
	if digest != first.policyDigest || counts == nil || counts.Deny != first.counts.Deny {
		t.Fatalf("preview digest=%s counts=%+v", digest, counts)
	}
}

func TestInstalledPolicyArtifactsRejectIncompleteManagedPair(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := systemdSetupPlan(setupSystemdOptions{SystemdOptions: bksetup.SystemdOptions{ConfigDir: configDir}})
	if err := os.WriteFile(plan.policyProfilePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installedGitHubPolicyArtifacts(plan); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("installedGitHubPolicyArtifacts() error = %v", err)
	}
}

func TestCheckGitHubPolicyReplacementRequiresExplicitFlag(t *testing.T) {
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	plan := systemdSetupPlan(setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{ConfigDir: configDir, ClientName: "agent-a"},
		PolicyPreset:   policypreset.RequestAllAgentOperations,
	})
	if err := os.WriteFile(plan.scopePath, []byte(minimalScopeJSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := checkGitHubPolicyReplacement(&stdout, plan); err == nil || !strings.Contains(err.Error(), "--replace-policy") {
		t.Fatalf("checkGitHubPolicyReplacement() error = %v", err)
	}
	plan.opts.ReplacePolicy = true
	if err := checkGitHubPolicyReplacement(&stdout, plan); err != nil {
		t.Fatalf("checkGitHubPolicyReplacement(replace) error = %v", err)
	}
	if !strings.Contains(stdout.String(), "Policy replacement preview") {
		t.Fatalf("replacement preview missing:\n%s", stdout.String())
	}
}

func TestCustomScopeRemovesManagedPresetEvidence(t *testing.T) {
	dir := t.TempDir()
	plan := systemdSetupPlan(setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			ConfigDir: filepath.Join(dir, "config"), StateDir: filepath.Join(dir, "state"), SystemdDir: filepath.Join(dir, "systemd"),
			User: "service", Group: "service", ClientName: "agent-a", Endpoint: testGHAgentEndpoint, BinaryPath: "/usr/local/bin/gh-broker",
		},
		ScopeFile:       writeFixture(t, dir, "scope.json", minimalScopeJSON()),
		GitHubTokenFile: writeFixture(t, dir, "token", "token\n"), DevTokenFallback: true,
		SharedSecret: strings.Repeat("s", 32), OperatorID: "operator-a", OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: testGHOperatorEndpoint,
	})
	installPlan, err := brokerkitSystemdInstallPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ghPolicyProfileFileName, ghPolicyManifestFileName} {
		if !slices.ContainsFunc(installPlan.RemoveFiles, func(file bkservice.ManagedFileRef) bool { return file.Name == name }) {
			t.Fatalf("managed preset evidence %s is not retired", name)
		}
	}
}

func assertTextExcludes(t *testing.T, text string, value string) {
	t.Helper()
	if strings.Contains(text, value) {
		t.Fatalf("text leaked protected value:\n%s", text)
	}
}

func TestBrokerkitSystemdPlanMapsGitHubAppCredentials(t *testing.T) {
	dir := t.TempDir()
	appIDFile := writeFixture(t, dir, "app-id", "12345\n")
	privateKeyFile := writeFixture(t, dir, "private-key.pem", "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n")
	clientIDFile := writeFixture(t, dir, "client-id", "Iv1.fixture\n")
	clientSecretFile := writeFixture(t, dir, "client-secret", "oauth-client-fixture\n")
	webhookSecretFile := writeFixture(t, dir, "webhook-secret", "webhook-fixture\n")
	plan := systemdSetupPlan(setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ConfigDir: filepath.Join(dir, "etc", "gh-broker"), StateDir: filepath.Join(dir, "var", "lib", "gh-broker"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/gh-broker",
			ClientName: "agent-a", Endpoint: testGHAgentEndpoint, NoStart: true,
		},
		GitHubAppIDFile:           appIDFile,
		GitHubAppPrivateKeyFile:   privateKeyFile,
		GitHubAppClientIDFile:     clientIDFile,
		GitHubAppClientSecretFile: clientSecretFile,
		GitHubUserID:              1234,
		GitHubWebhookSecretFile:   webhookSecretFile,
		ScopeFile:                 writeFixture(t, dir, "scope.json", minimalScopeJSON()),
		SharedSecret:              strings.Repeat("s", 32),
		OperatorID:                "operator-a",
		OperatorSecret:            strings.Repeat("o", 32),
		OperatorEndpoint:          testGHOperatorEndpoint,
	})
	installPlan, err := brokerkitSystemdInstallPlan(plan)
	if err != nil {
		t.Fatalf("brokerkitSystemdInstallPlan() error = %v", err)
	}
	if installPlan.ReadyCheck == nil {
		t.Fatal("Telegram credential retirement requires a readiness check")
	}
	wantOwners := map[string]bkservice.ManagedFileOwner{
		githubAppIDFileName:           bkservice.ManagedFileOwnerRoot,
		githubAppPrivateKeyFileName:   bkservice.ManagedFileOwnerService,
		githubAppClientIDFileName:     bkservice.ManagedFileOwnerRoot,
		githubAppClientSecretFileName: bkservice.ManagedFileOwnerService,
		githubWebhookSecretFileName:   bkservice.ManagedFileOwnerService,
		ghSecretsFileName:             bkservice.ManagedFileOwnerService,
		ghOperatorSecretsFileName:     bkservice.ManagedFileOwnerService,
		ghScopeFileName:               bkservice.ManagedFileOwnerRoot,
		ghEnvFileName:                 bkservice.ManagedFileOwnerRoot,
	}
	for _, file := range installPlan.Files {
		if file.Owner != wantOwners[file.Name] {
			t.Fatalf("managed file %s owner = %q, want %q", file.Name, file.Owner, wantOwners[file.Name])
		}
		delete(wantOwners, file.Name)
	}
	if len(wantOwners) != 0 {
		t.Fatalf("missing managed files: %v", wantOwners)
	}
	env := ""
	for _, file := range installPlan.Files {
		if file.Name == ghEnvFileName {
			env = string(file.Data)
		}
	}
	for _, want := range []string{"GH_BROKER_GITHUB_USER_ID=1234", "GH_BROKER_GITHUB_APP_CLIENT_ID_FILE=", "GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE="} {
		if !strings.Contains(env, want) {
			t.Fatalf("env missing %q:\n%s", want, env)
		}
	}
}

func TestGitHubInstallReadinessFollowsManagedRetirements(t *testing.T) {
	plan := systemdPlan{opts: setupSystemdOptions{
		SystemdOptions:       bksetup.SystemdOptions{Endpoint: testGHAgentEndpoint},
		TelegramBotTokenFile: "/tmp/telegram-token",
	}}
	if check := githubInstallReadyCheck(plan, []bkservice.ManagedFileRef{{Name: githubTokenFileName}}); check == nil {
		t.Fatal("managed retirement with Telegram configured requires a readiness check")
	}
	if check := githubInstallReadyCheck(plan, nil); check != nil {
		t.Fatal("installation without managed retirement does not require a readiness check")
	}
}

func TestValidateSetupSystemdOptions(t *testing.T) {
	base := bksetup.SystemdOptions{
		BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
		ConfigDir: "/etc/gh-broker", StateDir: "/var/lib/gh-broker",
		SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/gh-broker",
		ClientName: "agent-a", Endpoint: testGHAgentEndpoint,
		AgentUser: "agent-user", OperatorUser: "operator-user",
		AgentAccessGroup: "gh-broker-agent", OperatorAccessGroup: "gh-broker-operator",
	}
	valid := setupSystemdOptions{
		SystemdOptions:   base,
		ScopeFile:        "/tmp/scope.json",
		GitHubTokenFile:  "/tmp/token",
		SharedSecret:     strings.Repeat("s", 32),
		DevTokenFallback: true,
		OperatorID:       "operator-a", OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: testGHOperatorEndpoint,
	}
	if err := validateSetupSystemdOptions(valid); err != nil {
		t.Fatalf("validateSetupSystemdOptions() error = %v", err)
	}
	validApp := setupSystemdOptions{ // #nosec G101 -- test fixture paths and generated secrets are not credentials.
		SystemdOptions:          base,
		ScopeFile:               "/tmp/scope.json",
		GitHubAppIDFile:         "/tmp/app-id",
		GitHubAppPrivateKeyFile: "/tmp/key",
		GitHubWebhookSecretFile: "/tmp/webhook",
		SharedSecret:            strings.Repeat("s", 32),
		OperatorID:              "operator-a", OperatorSecret: strings.Repeat("o", 32), OperatorEndpoint: testGHOperatorEndpoint,
	}
	if err := validateSetupSystemdOptions(validApp); err != nil {
		t.Fatalf("validateSetupSystemdOptions(app) error = %v", err)
	}
	validApp.GitHubAppClientIDFile = "/tmp/client-id"
	validApp.GitHubAppClientSecretFile = "/tmp/client-secret"
	if err := validateSetupSystemdOptions(validApp); err == nil || !strings.Contains(err.Error(), "--github-user-id") {
		t.Fatalf("OAuth app setup without user id error = %v", err)
	}
	validApp.GitHubUserID = 1234
	if err := validateSetupSystemdOptions(validApp); err != nil {
		t.Fatalf("validateSetupSystemdOptions(user credential) error = %v", err)
	}
	cases := []func(*setupSystemdOptions){
		func(opts *setupSystemdOptions) { opts.PolicyPresetExplicit = true },
		func(opts *setupSystemdOptions) { opts.GitHubTokenFile = "" },
		func(opts *setupSystemdOptions) { opts.ClientName = "bad=name" },
		func(opts *setupSystemdOptions) { opts.SharedSecret = "short" },
		func(opts *setupSystemdOptions) { opts.Endpoint = "" },
		func(opts *setupSystemdOptions) { opts.OperatorID = "bad=name" },
		func(opts *setupSystemdOptions) { opts.OperatorEndpoint = "" },
		func(opts *setupSystemdOptions) { opts.OperatorEndpoint = opts.Endpoint },
		func(opts *setupSystemdOptions) { opts.OperatorSecret = opts.SharedSecret },
		func(opts *setupSystemdOptions) { opts.TelegramBotTokenFile = "/tmp/token" },
		func(opts *setupSystemdOptions) { opts.TelegramChatID = 123 },
	}
	for _, mutate := range cases {
		opts := valid
		mutate(&opts)
		if err := validateSetupSystemdOptions(opts); err == nil {
			t.Fatalf("validateSetupSystemdOptions(%+v) error = nil", opts)
		}
	}
}

func TestValidateGitHubAppSetupUserCredentialPair(t *testing.T) {
	base := setupSystemdOptions{GitHubAppIDFile: "app-id", GitHubAppPrivateKeyFile: "key", GitHubWebhookSecretFile: "webhook"}
	tests := []struct {
		name    string
		mutate  func(*setupSystemdOptions)
		wantErr bool
	}{
		{"base app", func(*setupSystemdOptions) {}, false},
		{"missing app", func(value *setupSystemdOptions) { value.GitHubAppIDFile = "" }, true},
		{"unpaired client", func(value *setupSystemdOptions) { value.GitHubAppClientIDFile = "client" }, true},
		{"missing user id", func(value *setupSystemdOptions) {
			value.GitHubAppClientIDFile, value.GitHubAppClientSecretFile = "client", "secret"
		}, true},
		{"orphan user id", func(value *setupSystemdOptions) { value.GitHubUserID = 1234 }, true},
		{"user credential", func(value *setupSystemdOptions) {
			value.GitHubAppClientIDFile, value.GitHubAppClientSecretFile, value.GitHubUserID = "client", "secret", 1234
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base
			test.mutate(&value)
			if err := validateGitHubAppSetup(value); (err != nil) != test.wantErr {
				t.Fatalf("validateGitHubAppSetup() error = %v", err)
			}
		})
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

func writeFixture(t *testing.T, dir string, name string, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func minimalScopeJSON() string {
	return `{"rules":[{"id":"bob-list","effect":"allow","clients":["bob"],"operations":["installation.repo.list"],"targets":[{"kind":"installation"}]}]}`
}

type recordingRunner struct {
	calls []string
	fail  map[string]bool
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) error {
	call := strings.Join(append([]string{name}, args...), " ")
	r.calls = append(r.calls, call)
	if r.fail[call] {
		return os.ErrNotExist
	}
	return nil
}
