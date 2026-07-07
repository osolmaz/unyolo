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
		User:         "hf-broker",
		Group:        "hf-broker",
		ConfigDir:    "/etc/hf-broker",
		StateDir:     "/var/lib/hf-broker",
		SystemdDir:   "/etc/systemd/system",
		BinaryPath:   "/usr/local/bin/hf-broker",
		HFTokenFile:  "/tmp/hf-token",
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		ClientName:   "agent",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
		BindAddr:     "127.0.0.1",
		Port:         8080,
	}
	plan := systemdSetupPlan(opts)
	scopeJSON, err := renderScopeJSON(opts.Repo, opts.RepoType)
	if err != nil {
		t.Fatalf("renderScopeJSON() error = %v", err)
	}
	scopeText := string(scopeJSON)
	for _, want := range []string{`"id": "osolmaz/scraped-news"`, `"type": "dataset"`, `"mode": "append-only"`} {
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
	unit := renderSystemdUnit(plan)
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
		User:         "hf-broker",
		Group:        "hf-broker",
		ConfigDir:    "/etc/hf-broker",
		StateDir:     "/var/lib/hf-broker",
		SystemdDir:   "/etc/systemd/system",
		BinaryPath:   "/usr/local/bin/hf-broker",
		HFTokenFile:  "/tmp/hf-token",
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		ClientName:   "agent",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
		BindAddr:     "127.0.0.1",
		Port:         8080,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "http://127.0.0.1:8080/datasets/osolmaz/scraped-news") {
		t.Fatalf("dry-run output = %q", stdout.String())
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
		User:          currentUser.Username,
		Group:         currentGroup.Name,
		ConfigDir:     filepath.Join(dir, "etc", "hf-broker"),
		StateDir:      filepath.Join(dir, "var", "lib", "hf-broker"),
		SystemdDir:    filepath.Join(dir, "systemd"),
		BinaryPath:    "/usr/local/bin/hf-broker",
		HFTokenFile:   tokenFile,
		Repo:          "osolmaz/scraped-news",
		RepoType:      "dataset",
		ClientName:    "agent",
		SharedSecret:  "abcdefghijklmnopqrstuvwxyz123456",
		BindAddr:      "127.0.0.1",
		Port:          8080,
		AllowNonRoot:  true,
		NoStart:       true,
		CommandRunner: &recordingRunner{},
	})
	if err != nil {
		t.Fatalf("runSetupSystemd() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "hf-broker systemd service configured") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestWriteSystemdPayloads(t *testing.T) {
	currentUser, currentGroup := currentUserAndGroup(t)
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "source-token")
	if err := os.WriteFile(tokenFile, []byte("hf_xxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := setupSystemdOptions{
		User:         currentUser.Username,
		Group:        currentGroup.Name,
		ConfigDir:    filepath.Join(dir, "etc", "hf-broker"),
		StateDir:     filepath.Join(dir, "var", "lib", "hf-broker"),
		SystemdDir:   filepath.Join(dir, "systemd"),
		BinaryPath:   "/usr/local/bin/hf-broker",
		HFTokenFile:  tokenFile,
		Repo:         "osolmaz/scraped-news",
		RepoType:     "dataset",
		ClientName:   "agent",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
		BindAddr:     "127.0.0.1",
		Port:         8080,
	}
	plan := systemdSetupPlan(opts)
	if err := writeSystemdPayloads(plan); err != nil {
		t.Fatalf("writeSystemdPayloads() error = %v", err)
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
	if err := chownSystemdFiles(plan, os.Getuid(), os.Getuid(), os.Getgid()); err != nil {
		t.Fatalf("chownSystemdFiles() error = %v", err)
	}
}

func TestWriteSystemdSetupFilesRejectsUnknownUser(t *testing.T) {
	dir := t.TempDir()
	opts := setupSystemdOptions{
		User:        "hf-broker-user-does-not-exist",
		Group:       "hf-broker-group-does-not-exist",
		ConfigDir:   filepath.Join(dir, "etc", "hf-broker"),
		StateDir:    filepath.Join(dir, "var", "lib", "hf-broker"),
		SystemdDir:  filepath.Join(dir, "systemd"),
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
		NoStart:       true,
		CommandRunner: runner,
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
		User:          "hf-broker",
		Group:         "hf-broker",
		StateDir:      "/var/lib/hf-broker",
		CommandRunner: runner,
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

func TestValidateSetupClient(t *testing.T) {
	valid := setupSystemdOptions{
		ClientName:   "agent",
		SharedSecret: "abcdefghijklmnopqrstuvwxyz123456",
	}
	if err := validateSetupClient(valid); err != nil {
		t.Fatalf("validateSetupClient() error = %v", err)
	}
	for _, opts := range []setupSystemdOptions{
		{SharedSecret: valid.SharedSecret},
		{ClientName: "agent", SharedSecret: "short"},
		{ClientName: "bad=name", SharedSecret: valid.SharedSecret},
		{ClientName: "agent", SharedSecret: valid.SharedSecret + "\n"},
	} {
		if err := validateSetupClient(opts); err == nil {
			t.Fatalf("validateSetupClient(%+v) error = nil", opts)
		}
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
