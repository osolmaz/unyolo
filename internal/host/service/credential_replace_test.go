package service

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestValidateCredentialReplacePlanFailures(t *testing.T) {
	dir := t.TempDir()
	valid := credentialTestPlan(dir, []ManagedFile{{Area: ManagedFileConfig, Name: "token", Data: []byte("value"), Mode: 0o600,
		Owner: ManagedFileOwnerService, CredentialClass: "provider-access"}})
	tests := []struct {
		name   string
		mutate func(*CredentialReplacePlan)
	}{
		{"provider", func(plan *CredentialReplacePlan) { plan.Provider = "" }},
		{"relative directory", func(plan *CredentialReplacePlan) { plan.ConfigDir = "relative" }},
		{"root directory", func(plan *CredentialReplacePlan) { plan.ConfigDir = "/" }},
		{"user", func(plan *CredentialReplacePlan) { plan.User = "" }},
		{"group", func(plan *CredentialReplacePlan) { plan.Group = "" }},
		{"files", func(plan *CredentialReplacePlan) { plan.Files = nil }},
		{"area", func(plan *CredentialReplacePlan) { plan.Files[0].Area = ManagedFileState }},
		{"name", func(plan *CredentialReplacePlan) { plan.Files[0].Name = "../token" }},
		{"class", func(plan *CredentialReplacePlan) { plan.Files[0].CredentialClass = "" }},
		{"duplicate", func(plan *CredentialReplacePlan) { plan.Files = append(plan.Files, plan.Files[0]) }},
		{"mode", func(plan *CredentialReplacePlan) { plan.Files[0].Mode = 0o777 }},
	}
	if runtime.GOOS == "linux" {
		tests = append(tests, struct {
			name   string
			mutate func(*CredentialReplacePlan)
		}{"unit", func(plan *CredentialReplacePlan) { plan.SystemdUnit = "bad" }})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan := valid
			plan.Files = append([]ManagedFile(nil), valid.Files...)
			test.mutate(&plan)
			if err := validateCredentialReplacePlan(plan); err == nil {
				t.Fatal("invalid replacement plan succeeded")
			}
		})
	}
}

func TestCredentialReplacementHelpersRestoreAndCheckReadiness(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := openCredentialRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	files := []ManagedFile{
		{Area: ManagedFileConfig, Name: "old", Data: []byte("after"), Mode: 0o600, Owner: ManagedFileOwnerService, CredentialClass: "test"},
		{Area: ManagedFileConfig, Name: "new", Data: []byte("new"), Mode: 0o600, Owner: ManagedFileOwnerService, CredentialClass: "test"},
	}
	snapshots, err := captureCredentialFiles(root, files)
	if err != nil {
		t.Fatal(err)
	}
	defer clearCredentialSnapshots(snapshots)
	if err := writeCredentialFiles(root, files, os.Geteuid(), os.Getegid(), true); err != nil {
		t.Fatal(err)
	}
	if err := restoreCredentialFiles(root, snapshots, os.Geteuid(), os.Getegid(), true); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "old"))
	if string(data) != "before" {
		t.Fatalf("restored old file = %q", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new file remained after restore: %v", err)
	}

	plan := credentialTestPlan(dir, files)
	plan.AllowNonRoot = false
	plan.ReadyCheck = func(context.Context) error { return nil }
	if err := waitForCredentialReady(t.Context(), plan); err != nil {
		t.Fatal(err)
	}
	plan.ReadyCheck = func(context.Context) error { return errors.New("not ready") }
	plan.ReadyTimeout, plan.ReadyInterval = time.Nanosecond, time.Nanosecond
	if err := waitForCredentialReady(t.Context(), plan); !errors.Is(err, errServiceReadinessFailed) {
		t.Fatalf("readiness error = %v", err)
	}
	runner := &credentialRecordingRunner{}
	plan.Runner = runner
	wantRestartTarget := "hf-broker.service"
	if runtime.GOOS == "darwin" {
		wantRestartTarget = "io.unyolo.hf-broker"
	}
	if err := restartCredentialService(t.Context(), runner, plan); err != nil || len(runner.calls) != 1 || !strings.Contains(runner.calls[0], wantRestartTarget) {
		t.Fatalf("restart calls = %v, %v", runner.calls, err)
	}
}

func TestOpenCredentialRootRejectsRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openCredentialRoot(path); err == nil {
		t.Fatal("regular file accepted as credential root")
	}
}

func TestCredentialOwnerIdentityHelpers(t *testing.T) {
	plan := credentialTestPlan(t.TempDir(), []ManagedFile{{Area: ManagedFileConfig, Name: "token", Data: []byte("value"), Mode: 0o600,
		Owner: ManagedFileOwnerService, CredentialClass: "test"}})
	plan.AllowNonRoot = false
	plan.User, plan.Group = currentIdentity(t)
	uid, gid, err := credentialOwnerIDs(plan)
	if err != nil || uid < 0 || gid < 0 {
		t.Fatalf("credential owner IDs = %d:%d, %v", uid, gid, err)
	}
	plan.User = "unyolo-user-does-not-exist"
	if _, _, err := credentialOwnerIDs(plan); err == nil {
		t.Fatal("missing credential user was accepted")
	}
	plan.User, plan.Group = currentIdentity(t)
	plan.Group = "unyolo-group-does-not-exist"
	if _, _, err := credentialOwnerIDs(plan); err == nil {
		t.Fatal("missing credential group was accepted")
	}
}

func credentialTestPlan(dir string, files []ManagedFile) CredentialReplacePlan {
	return CredentialReplacePlan{
		Provider: "test", User: "test", Group: "test", ConfigDir: dir, Files: files, SystemdUnit: "hf-broker.service",
		LaunchdLabel: "io.unyolo.hf-broker", AllowNonRoot: true,
	}
}

func currentIdentity(t *testing.T) (string, string) {
	t.Helper()
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	return current.Username, group.Name
}

type credentialRecordingRunner struct {
	calls       []string
	contextErrs []error
}

func (r *credentialRecordingRunner) Run(ctx context.Context, name string, args ...string) error {
	r.calls = append(r.calls, name+" "+args[len(args)-1])
	r.contextErrs = append(r.contextErrs, ctx.Err())
	return nil
}
