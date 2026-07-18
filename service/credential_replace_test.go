package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceCredentialWritesExactFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(old, []byte("hf_old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan := credentialTestPlan(dir, []ManagedFile{{
		Area: ManagedFileConfig, Name: "hf-token", Data: []byte("hf_new\n"), Mode: 0o600,
		Owner: ManagedFileOwnerService, CredentialClass: "huggingface-access",
	}})
	if err := ReplaceCredential(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(old)
	if err != nil || string(data) != "hf_new\n" {
		t.Fatalf("credential = %q err=%v", data, err)
	}
}

func TestReplaceCredentialRollsBackAllFilesWhenReadinessFails(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{"hf-token": "hf_old\n", "credential-status.json": "old metadata\n"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runner := &credentialRecordingRunner{}
	plan := credentialTestPlan(dir, []ManagedFile{
		{Area: ManagedFileConfig, Name: "hf-token", Data: []byte("hf_new\n"), Mode: 0o600, Owner: ManagedFileOwnerService, CredentialClass: "huggingface-access"},
		{Area: ManagedFileConfig, Name: "credential-status.json", Data: []byte("new metadata\n"), Mode: 0o640, Owner: ManagedFileOwnerRoot, CredentialClass: "huggingface-access-metadata"},
	})
	plan.AllowNonRoot = false
	plan.User, plan.Group = currentIdentity(t)
	plan.Runner = runner
	plan.ReadyCheck = func(context.Context) error { return errors.New("not ready") }
	plan.ReadyTimeout = 1
	if os.Geteuid() != 0 {
		t.Skip("root-only activation path")
	}
	if err := ReplaceCredential(context.Background(), plan); err == nil {
		t.Fatal("ReplaceCredential() succeeded")
	}
	for name, want := range map[string]string{"hf-token": "hf_old\n", "credential-status.json": "old metadata\n"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != want {
			t.Fatalf("%s = %q err=%v", name, data, err)
		}
	}
	if len(runner.calls) != 2 {
		t.Fatalf("restart calls = %v", runner.calls)
	}
}

func TestReplaceCredentialRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "hf-token")); err != nil {
		t.Fatal(err)
	}
	plan := credentialTestPlan(dir, []ManagedFile{{
		Area: ManagedFileConfig, Name: "hf-token", Data: []byte("hf_new\n"), Mode: 0o600,
		Owner: ManagedFileOwnerService, CredentialClass: "huggingface-access",
	}})
	if err := ReplaceCredential(context.Background(), plan); err == nil {
		t.Fatal("ReplaceCredential() accepted symlink")
	}
}

func credentialTestPlan(dir string, files []ManagedFile) CredentialReplacePlan {
	return CredentialReplacePlan{
		Provider: "test", User: "test", Group: "test", ConfigDir: dir, Files: files, SystemdUnit: "hf-broker.service",
		AllowNonRoot: true,
	}
}

func currentIdentity(t *testing.T) (string, string) {
	t.Helper()
	return "root", "root"
}

type credentialRecordingRunner struct{ calls []string }

func (r *credentialRecordingRunner) Run(_ context.Context, name string, args ...string) error {
	r.calls = append(r.calls, name+" "+args[len(args)-1])
	return nil
}
