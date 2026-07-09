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
		User:             "gh-broker",
		Group:            "gh-broker",
		ConfigDir:        "/etc/gh-broker",
		StateDir:         "/var/lib/gh-broker",
		SystemdDir:       "/etc/systemd/system",
		BinaryPath:       "/usr/local/bin/gh-broker",
		GitHubTokenFile:  "/tmp/github-token",
		ScopeFile:        "/tmp/scope.json",
		ClientName:       "bob",
		SharedSecret:     strings.Repeat("s", 32),
		BindAddr:         "127.0.0.1",
		Port:             8081,
		DevTokenFallback: true,
		DryRun:           true,
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
		User:                    "gh-broker",
		Group:                   "gh-broker",
		ConfigDir:               "/etc/gh-broker",
		StateDir:                "/var/lib/gh-broker",
		SystemdDir:              "/etc/systemd/system",
		BinaryPath:              "/usr/local/bin/gh-broker",
		GitHubAppIDFile:         "/tmp/app-id",
		GitHubAppPrivateKeyFile: "/tmp/private-key.pem",
		GitHubWebhookSecretFile: "/tmp/webhook-secret",
		ScopeFile:               "/tmp/scope.json",
		ClientName:              "bob",
		SharedSecret:            strings.Repeat("s", 32),
		BindAddr:                "0.0.0.0",
		Port:                    8081,
		DryRun:                  true,
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
	scopeFile := writeFixture(t, dir, "scope.json", minimalScopeJSON())
	var stdout bytes.Buffer
	err := runSetupSystemd(context.Background(), &stdout, setupSystemdOptions{
		User:             currentUser.Username,
		Group:            currentGroup.Name,
		ConfigDir:        filepath.Join(dir, "etc", "gh-broker"),
		StateDir:         filepath.Join(dir, "var", "lib", "gh-broker"),
		SystemdDir:       filepath.Join(dir, "systemd"),
		BinaryPath:       "/usr/local/bin/gh-broker",
		GitHubTokenFile:  tokenFile,
		ScopeFile:        scopeFile,
		ClientName:       "bob",
		SharedSecret:     strings.Repeat("s", 32),
		BindAddr:         "127.0.0.1",
		Port:             8081,
		DevTokenFallback: true,
		AllowNonRoot:     true,
		NoStart:          true,
		CommandRunner:    &recordingRunner{},
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "gh-broker systemd service configured") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	for _, path := range []string{
		filepath.Join(dir, "etc", "gh-broker", "github-token"),
		filepath.Join(dir, "etc", "gh-broker", "secrets"),
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
	} {
		if !strings.Contains(envText, want) {
			t.Fatalf("env missing %q:\n%s", want, envText)
		}
	}
	if strings.Contains(envText, strings.Repeat("s", 32)) {
		t.Fatalf("env leaked broker secret:\n%s", envText)
	}
}

func TestWriteGitHubAppCredentialFiles(t *testing.T) {
	dir := t.TempDir()
	appIDFile := writeFixture(t, dir, "app-id", "12345\n")
	privateKeyFile := writeFixture(t, dir, "private-key.pem", "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n")
	webhookSecretFile := writeFixture(t, dir, "webhook-secret", "webhook-fixture\n")
	plan := systemdSetupPlan(setupSystemdOptions{
		ConfigDir:               filepath.Join(dir, "etc", "gh-broker"),
		StateDir:                filepath.Join(dir, "var", "lib", "gh-broker"),
		SystemdDir:              filepath.Join(dir, "systemd"),
		GitHubAppIDFile:         appIDFile,
		GitHubAppPrivateKeyFile: privateKeyFile,
		GitHubWebhookSecretFile: webhookSecretFile,
	})
	if err := createSystemdDirs(plan); err != nil {
		t.Fatalf("createSystemdDirs() error = %v", err)
	}
	if err := writeGitHubAppCredentialFiles(plan); err != nil {
		t.Fatalf("writeGitHubAppCredentialFiles() error = %v", err)
	}
	for _, path := range []string{plan.appIDPath, plan.appPrivateKeyPath, plan.webhookSecretPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
}

func TestStartSystemdServiceNoStartAndRun(t *testing.T) {
	runner := &recordingRunner{}
	if err := startSystemdService(context.Background(), setupSystemdOptions{NoStart: true, CommandRunner: runner}); err != nil {
		t.Fatalf("startSystemdService(no-start) error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("no-start calls = %v, want none", runner.calls)
	}
	if err := startSystemdService(context.Background(), setupSystemdOptions{CommandRunner: runner}); err != nil {
		t.Fatalf("startSystemdService(run) error = %v", err)
	}
	got := strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"systemctl daemon-reload",
		"systemctl enable --now gh-broker.service",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("calls missing %q:\n%s", want, got)
		}
	}
}

func TestEnsureServiceAccountCreatesMissingParts(t *testing.T) {
	runner := &recordingRunner{fail: map[string]bool{
		"getent group gh-broker": true,
		"id -u gh-broker":        true,
	}}
	err := ensureServiceAccount(context.Background(), setupSystemdOptions{
		User:          "gh-broker",
		Group:         "gh-broker",
		StateDir:      "/var/lib/gh-broker",
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatalf("ensureServiceAccount() error = %v", err)
	}
	got := strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"groupadd --system gh-broker",
		"useradd --system --gid gh-broker --home-dir /var/lib/gh-broker --shell /usr/sbin/nologin gh-broker",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("calls missing %q:\n%s", want, got)
		}
	}
}

func TestParseServiceIDs(t *testing.T) {
	uid, gid, err := parseServiceIDs("user", "1000", "group", "1001")
	if err != nil {
		t.Fatalf("parseServiceIDs() error = %v", err)
	}
	if uid != 1000 || gid != 1001 {
		t.Fatalf("parseServiceIDs() = %d, %d", uid, gid)
	}
	if _, _, err := parseServiceIDs("user", "bad", "group", "1001"); err == nil {
		t.Fatal("parseServiceIDs() bad uid error = nil")
	}
	if _, _, err := parseServiceIDs("user", "1000", "group", "bad"); err == nil {
		t.Fatal("parseServiceIDs() bad gid error = nil")
	}
}

func TestValidateSetupSystemdOptions(t *testing.T) {
	valid := setupSystemdOptions{
		ScopeFile:        "/tmp/scope.json",
		GitHubTokenFile:  "/tmp/token",
		ClientName:       "bob",
		SharedSecret:     strings.Repeat("s", 32),
		Port:             8081,
		DevTokenFallback: true,
	}
	if err := validateSetupSystemdOptions(valid); err != nil {
		t.Fatalf("validateSetupSystemdOptions() error = %v", err)
	}
	cases := []setupSystemdOptions{
		{GitHubTokenFile: valid.GitHubTokenFile, ClientName: valid.ClientName, SharedSecret: valid.SharedSecret, Port: valid.Port, DevTokenFallback: true},
		{ScopeFile: valid.ScopeFile, ClientName: valid.ClientName, SharedSecret: valid.SharedSecret, Port: valid.Port, DevTokenFallback: true},
		{ScopeFile: valid.ScopeFile, GitHubTokenFile: valid.GitHubTokenFile, SharedSecret: valid.SharedSecret, Port: valid.Port, DevTokenFallback: true},
		{ScopeFile: valid.ScopeFile, GitHubTokenFile: valid.GitHubTokenFile, ClientName: "bad=name", SharedSecret: valid.SharedSecret, Port: valid.Port, DevTokenFallback: true},
		{ScopeFile: valid.ScopeFile, GitHubTokenFile: valid.GitHubTokenFile, ClientName: valid.ClientName, SharedSecret: "short", Port: valid.Port, DevTokenFallback: true},
		{ScopeFile: valid.ScopeFile, GitHubTokenFile: valid.GitHubTokenFile, ClientName: valid.ClientName, SharedSecret: valid.SharedSecret, DevTokenFallback: true},
		{ScopeFile: valid.ScopeFile, GitHubAppIDFile: "/tmp/app-id", GitHubAppPrivateKeyFile: "/tmp/key", GitHubWebhookSecretFile: "/tmp/webhook", ClientName: valid.ClientName, SharedSecret: valid.SharedSecret, Port: valid.Port}, // #nosec G101 -- test fixture paths are not credentials.
	}
	for _, opts := range cases {
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
