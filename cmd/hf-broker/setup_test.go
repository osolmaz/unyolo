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
		HFTokenFile:   tokenFile,
		Repo:          "osolmaz/scraped-news",
		RepoType:      "dataset",
		SharedSecret:  "abcdefghijklmnopqrstuvwxyz123456",
		CommandRunner: &recordingRunner{},
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
}

func TestWriteSystemdSetupFiles(t *testing.T) {
	currentUser, currentGroup := currentUserAndGroup(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "source-token")
	if err := os.WriteFile(tokenFile, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			BrokerName: "hf-broker", User: currentUser.Username, Group: currentGroup.Name,
			ConfigDir: filepath.Join(dir, "etc", "hf-broker"), StateDir: filepath.Join(dir, "var", "lib", "hf-broker"),
			SystemdDir: filepath.Join(dir, "systemd"), BinaryPath: "/usr/local/bin/hf-broker",
			ClientName: "agent", BindAddr: "127.0.0.1", Port: 8080, AllowNonRoot: true,
		},
		HFTokenFile:  tokenFile,
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
	}
	plan := systemdSetupPlan(opts)
	if err := writeSystemdSetupFiles(plan); err != nil {
		t.Fatalf("writeSystemdSetupFiles() error = %v", err)
	}
	for _, path := range []string{
		filepath.Join(opts.ConfigDir, "hf-token"),
		filepath.Join(opts.ConfigDir, "secrets"),
		filepath.Join(opts.ConfigDir, "scope.json"),
		filepath.Join(opts.ConfigDir, "env"),
		filepath.Join(opts.SystemdDir, "hf-broker.service"),
	} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s: %v", path, err)
		}
	}
}

func TestWriteSystemdSetupFilesRejectsUnknownUser(t *testing.T) {
	dir := t.TempDir()
	opts := setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{
			User: "hf-broker-user-does-not-exist", Group: "hf-broker-group-does-not-exist",
			ConfigDir: filepath.Join(dir, "etc", "hf-broker"), StateDir: filepath.Join(dir, "var", "lib", "hf-broker"),
			SystemdDir: filepath.Join(dir, "systemd"),
		},
		HFTokenFile: filepath.Join(dir, "token"),
	}
	err := writeSystemdSetupFiles(systemdSetupPlan(opts))
	if err == nil || !strings.Contains(err.Error(), "lookup user") {
		t.Fatalf("writeSystemdSetupFiles() error = %v, want lookup user", err)
	}
}

func TestStartSystemdServiceNoStart(t *testing.T) {
	runner := &recordingRunner{}
	err := startSystemdService(context.Background(), setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{NoStart: true},
		CommandRunner:  runner,
	})
	if err != nil {
		t.Fatalf("startSystemdService() error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("runner calls = %v, want none", runner.calls)
	}
}

func TestStartSystemdServiceRunsSystemctl(t *testing.T) {
	runner := &recordingRunner{}
	err := startSystemdService(context.Background(), setupSystemdOptions{
		CommandRunner: runner,
	})
	if err != nil {
		t.Fatalf("startSystemdService() error = %v", err)
	}
	got := strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"systemctl daemon-reload",
		"systemctl enable --now hf-broker.service",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("calls missing %q:\n%s", want, got)
		}
	}
}

func TestEnsureServiceAccountCreatesMissingParts(t *testing.T) {
	runner := &recordingRunner{fail: map[string]bool{
		"getent group hf-broker": true,
		"id -u hf-broker":        true,
	}}
	err := ensureServiceAccount(context.Background(), setupSystemdOptions{
		SystemdOptions: bksetup.SystemdOptions{User: "hf-broker", Group: "hf-broker", StateDir: "/var/lib/hf-broker"},
		CommandRunner:  runner,
	})
	if err != nil {
		t.Fatalf("ensureServiceAccount() error = %v", err)
	}
	got := strings.Join(runner.calls, "\n")
	for _, want := range []string{
		"groupadd --system hf-broker",
		"useradd --system --gid hf-broker --home-dir /var/lib/hf-broker --shell /usr/sbin/nologin hf-broker",
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

func TestCopySecretFileRejectsEmptyToken(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "empty")
	if err := os.WriteFile(source, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := copySecretFile(source, filepath.Join(dir, "dest"))
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("copySecretFile() error = %v, want empty", err)
	}
}

func TestCopySecretFileRejectsOversizedToken(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "large")
	if err := os.WriteFile(source, []byte(strings.Repeat("x", maxHFTokenBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	err := copySecretFile(source, filepath.Join(dir, "dest"))
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("copySecretFile() error = %v, want size limit", err)
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
