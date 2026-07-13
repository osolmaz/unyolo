//go:build linux

package main

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	bkservice "github.com/osolmaz/brokerkit/service"
	bksetup "github.com/osolmaz/brokerkit/setup"
)

func TestParseSetupSystemdRequiresScope(t *testing.T) {
	_, err := parseSetupSystemd(ioDiscard{}, strings.NewReader(""), nil)
	if err == nil || !strings.Contains(err.Error(), "--scope-file") {
		t.Fatalf("parseSetupSystemd() error = %v, want scope requirement", err)
	}
}

func TestParseSetupSystemdGeneratesSecret(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeFixture(t, dir, "github-token", "ghp_token\n")
	scopeFile := writeFixture(t, dir, "scope.json", minimalScopeJSON())
	opts, err := parseSetupSystemd(ioDiscard{}, strings.NewReader(""), []string{
		"--scope-file", scopeFile,
		"--github-token-file", tokenFile,
		"--dev-token-fallback",
	})
	if err != nil {
		t.Fatalf("parseSetupSystemd() error = %v", err)
	}
	if len(opts.SharedSecret) != 64 {
		t.Fatalf("generated secret length = %d, want 64", len(opts.SharedSecret))
	}
	if len(opts.OperatorSecret) != 64 || opts.OperatorID != "onur" || opts.OperatorPort != 8082 {
		t.Fatalf("generated operator config = %+v", opts)
	}
}

func TestParseSetupSystemdReadsSharedSecretFromFileAndStdin(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeFixture(t, dir, "github-token", "ghp_token\n")
	scopeFile := writeFixture(t, dir, "scope.json", minimalScopeJSON())
	secretFile := writeFixture(t, dir, "client-secret", strings.Repeat("s", 32)+"\n")
	opts, err := parseSetupSystemd(ioDiscard{}, strings.NewReader(""), []string{
		"--scope-file", scopeFile,
		"--github-token-file", tokenFile,
		"--dev-token-fallback",
		"--shared-secret-file", secretFile,
	})
	if err != nil {
		t.Fatalf("parseSetupSystemd(file) error = %v", err)
	}
	if opts.SharedSecret != strings.Repeat("s", 32) {
		t.Fatalf("SharedSecret from file = %q", opts.SharedSecret)
	}
	opts, err = parseSetupSystemd(ioDiscard{}, strings.NewReader(strings.Repeat("t", 32)+"\n"), []string{
		"--scope-file", scopeFile,
		"--github-token-file", tokenFile,
		"--dev-token-fallback",
		"--shared-secret-stdin",
	})
	if err != nil {
		t.Fatalf("parseSetupSystemd(stdin) error = %v", err)
	}
	if opts.SharedSecret != strings.Repeat("t", 32) {
		t.Fatalf("SharedSecret from stdin = %q", opts.SharedSecret)
	}
}

func TestSetupSystemdDryRunForDevTokenFallback(t *testing.T) {
	var stdout bytes.Buffer
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{ // #nosec G101 -- test fixture paths and generated secrets are not credentials.
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ConfigDir: "/etc/gh-broker", StateDir: "/var/lib/gh-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/gh-broker",
			ClientName: "bob", BindAddr: "127.0.0.1", Port: 8081, DryRun: true,
		},
		GitHubTokenFile: "/tmp/github-token",
		ScopeFile:       "/tmp/scope.json",
		SharedSecret:    strings.Repeat("s", 32),
		OperatorID:      "onur", OperatorSecret: strings.Repeat("o", 32), OperatorBindAddr: "127.0.0.1", OperatorPort: 8082,
		DevTokenFallback: true,
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	for _, want := range []string{
		"gh-broker systemd service",
		"token fallback:  true",
		"github token:    /etc/gh-broker/github-token",
		"broker URL:      http://127.0.0.1:8081",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("dry-run missing %q:\n%s", want, stdout.String())
		}
	}
}

func TestSetupSystemdDryRunForGitHubAppFiles(t *testing.T) {
	var stdout bytes.Buffer
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{ // #nosec G101 -- test fixture paths and generated secrets are not credentials.
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
			ConfigDir: "/etc/gh-broker", StateDir: "/var/lib/gh-broker",
			SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/gh-broker",
			ClientName: "bob", BindAddr: "0.0.0.0", Port: 8081, DryRun: true,
		},
		GitHubAppIDFile:         "/tmp/app-id",
		GitHubAppPrivateKeyFile: "/tmp/private-key.pem",
		GitHubWebhookSecretFile: "/tmp/webhook-secret",
		ScopeFile:               "/tmp/scope.json",
		SharedSecret:            strings.Repeat("s", 32),
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	for _, want := range []string{
		"token fallback:  false",
		"app id file:     /etc/gh-broker/github-app-id",
		"app private key: /etc/gh-broker/github-app-private-key.pem",
		"broker URL:      http://127.0.0.1:8081",
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
			ClientName: "bob", BindAddr: "127.0.0.1", Port: 8081, AllowNonRoot: true, NoStart: true,
		},
		GitHubTokenFile:      tokenFile,
		ScopeFile:            scopeFile,
		SharedSecret:         strings.Repeat("s", 32),
		OperatorID:           "onur",
		OperatorSecret:       strings.Repeat("o", 32),
		OperatorBindAddr:     "127.0.0.1",
		OperatorPort:         8082,
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
	if got := strings.Join(runner.calls, "\n"); got != "getent group "+currentGroup.Name+"\nid -u "+currentUser.Username {
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
		"GH_BROKER_OPERATOR_PORT=8082",
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
			ClientName: "bob", BindAddr: "127.0.0.1", Port: 8081, NoStart: true,
		},
		GitHubAppIDFile:           appIDFile,
		GitHubAppPrivateKeyFile:   privateKeyFile,
		GitHubAppClientIDFile:     clientIDFile,
		GitHubAppClientSecretFile: clientSecretFile,
		GitHubWebhookSecretFile:   webhookSecretFile,
		ScopeFile:                 writeFixture(t, dir, "scope.json", minimalScopeJSON()),
		SharedSecret:              strings.Repeat("s", 32),
		OperatorID:                "onur",
		OperatorSecret:            strings.Repeat("o", 32),
		OperatorBindAddr:          "127.0.0.1",
		OperatorPort:              8082,
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
	for _, want := range []string{"GH_BROKER_GITHUB_APP_CLIENT_ID_FILE=", "GH_BROKER_GITHUB_APP_CLIENT_SECRET_FILE="} {
		if !strings.Contains(env, want) {
			t.Fatalf("env missing %q:\n%s", want, env)
		}
	}
}

func TestValidateSetupSystemdOptions(t *testing.T) {
	base := bksetup.SystemdOptions{
		BrokerName: "gh-broker", User: "gh-broker", Group: "gh-broker",
		ConfigDir: "/etc/gh-broker", StateDir: "/var/lib/gh-broker",
		SystemdDir: "/etc/systemd/system", BinaryPath: "/usr/local/bin/gh-broker",
		ClientName: "bob", BindAddr: "127.0.0.1", Port: 8081,
	}
	valid := setupSystemdOptions{
		SystemdOptions:   base,
		ScopeFile:        "/tmp/scope.json",
		GitHubTokenFile:  "/tmp/token",
		SharedSecret:     strings.Repeat("s", 32),
		DevTokenFallback: true,
		OperatorID:       "onur", OperatorSecret: strings.Repeat("o", 32), OperatorBindAddr: "127.0.0.1", OperatorPort: 8082,
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
		OperatorID:              "onur", OperatorSecret: strings.Repeat("o", 32), OperatorBindAddr: "127.0.0.1", OperatorPort: 8082,
	}
	if err := validateSetupSystemdOptions(validApp); err != nil {
		t.Fatalf("validateSetupSystemdOptions(app) error = %v", err)
	}
	cases := []func(*setupSystemdOptions){
		func(opts *setupSystemdOptions) { opts.ScopeFile = "" },
		func(opts *setupSystemdOptions) { opts.GitHubTokenFile = "" },
		func(opts *setupSystemdOptions) { opts.ClientName = "bad=name" },
		func(opts *setupSystemdOptions) { opts.SharedSecret = "short" },
		func(opts *setupSystemdOptions) { opts.Port = 0 },
		func(opts *setupSystemdOptions) { opts.OperatorID = "bad=name" },
		func(opts *setupSystemdOptions) { opts.OperatorBindAddr = "" },
		func(opts *setupSystemdOptions) { opts.OperatorPort = opts.Port },
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
	return `{"rules":[{"id":"bob-list","effect":"allow","clients":["bob"],"operations":["installation.repos.list"],"targets":[{"kind":"installation"}]}]}`
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
