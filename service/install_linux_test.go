//go:build linux

package service

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInstallSystemdNonRootFixture(t *testing.T) {
	plan := nonRootInstallPlan(t)
	runner := &recordingCommandRunner{}
	plan.Runner = runner
	if err := InstallSystemd(context.Background(), plan); err != nil {
		t.Fatalf("InstallSystemd() error = %v", err)
	}
	if got := strings.Join(runner.calls, "\n"); got != "getent group "+plan.Group+"\nid -u "+plan.User {
		t.Fatalf("runner calls:\n%s", got)
	}
	assertInstalledFile(t, filepath.Join(plan.ConfigDir, "env"), "BIND=127.0.0.1\n", 0o640)
	assertInstalledFile(t, filepath.Join(plan.ConfigDir, "secret"), "opaque-secret", 0o600)
	assertInstalledFile(t, filepath.Join(plan.StateDir, "grants.json"), "{}\n", 0o600)
	unitPath := filepath.Join(plan.SystemdDir, plan.UnitName)
	data, err := os.ReadFile(unitPath) // #nosec G304 -- test reads its private fixture path.
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"User=" + plan.User, "EnvironmentFile=" + plan.Unit.EnvironmentFile, "ExecStart=/usr/bin/test"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("installed unit missing %q:\n%s", want, data)
		}
	}
	assertMode(t, plan.ConfigDir, 0o750)
	assertMode(t, plan.StateDir, 0o750)
	assertMode(t, plan.SystemdDir, 0o755)
}

func TestInstallSystemdRejectsInvalidOrUnprivilegedPlan(t *testing.T) {
	invalid := nonRootInstallPlan(t)
	invalid.UnitName = "invalid"
	if err := InstallSystemd(context.Background(), invalid); err == nil {
		t.Fatal("InstallSystemd(invalid) error = nil")
	}

	if os.Geteuid() == 0 {
		t.Skip("privilege rejection requires a non-root test process")
	}
	unprivileged := nonRootInstallPlan(t)
	unprivileged.AllowNonRoot = false
	if err := InstallSystemd(context.Background(), unprivileged); err == nil || !strings.Contains(err.Error(), "must run as root") {
		t.Fatalf("InstallSystemd(unprivileged) error = %v", err)
	}
}

func TestInstallSystemdReplacesManagedFileSymlink(t *testing.T) {
	plan := nonRootInstallPlan(t)
	if err := os.MkdirAll(plan.ConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(plan.ConfigDir), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(plan.ConfigDir, "env")); err != nil {
		t.Fatal(err)
	}
	plan.Runner = &recordingCommandRunner{}
	if err := InstallSystemd(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(outside) // #nosec G304 -- test reads its private fixture path.
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("outside file = %q, err=%v", data, err)
	}
	info, err := os.Lstat(filepath.Join(plan.ConfigDir, "env"))
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("installed env info = %+v, err=%v", info, err)
	}
}

func TestInstallSystemdOrdersSecretsBeforeEnvironment(t *testing.T) {
	plan := nonRootInstallPlan(t)
	if err := os.MkdirAll(plan.ConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plan.ConfigDir, "env"), []byte("OLD=1\n"), 0o640); err != nil { // #nosec G306 -- fixture mirrors the managed environment mode.
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(plan.ConfigDir, "secret"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan.Runner = &recordingCommandRunner{}
	if err := InstallSystemd(context.Background(), plan); err == nil {
		t.Fatal("InstallSystemd() error = nil")
	}
	assertInstalledFile(t, filepath.Join(plan.ConfigDir, "env"), "OLD=1\n", 0o640)
}

func TestInstallSystemdPreservesRetiredManagedFileWithoutActivation(t *testing.T) {
	plan := nonRootInstallPlan(t)
	if err := os.MkdirAll(plan.ConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	retired := filepath.Join(plan.ConfigDir, "retired-secret")
	if err := os.WriteFile(retired, []byte("old-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	plan.Runner = &recordingCommandRunner{}
	if err := InstallSystemd(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(retired); err != nil {
		t.Fatalf("retired managed file was removed without activation: %v", err)
	}
	assertInstalledFile(t, filepath.Join(plan.ConfigDir, "env"), "BIND=127.0.0.1\n", 0o640)
}

func TestInstallSystemdRemovesRetiredManagedFileAfterActivation(t *testing.T) {
	plan := nonRootInstallPlan(t)
	retired := prepareRetiredManagedFile(t, plan, "retired-secret")
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	installActivatedFixture(t, plan, &recordingCommandRunner{})
	if _, err := os.Lstat(retired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired managed file still exists: %v", err)
	}
}

func TestInstallSystemdRetiresSymlinkWithoutFollowingIt(t *testing.T) {
	plan := nonRootInstallPlan(t)
	if err := os.MkdirAll(plan.ConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(plan.ConfigDir), "outside-secret")
	if err := os.WriteFile(outside, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	retired := filepath.Join(plan.ConfigDir, "retired-secret")
	if err := os.Symlink(outside, retired); err != nil {
		t.Fatal(err)
	}
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	installActivatedFixture(t, plan, &recordingCommandRunner{})
	if data, err := os.ReadFile(outside); err != nil || string(data) != "unchanged" { // #nosec G304 -- controlled test fixture path.
		t.Fatalf("outside file = %q, err=%v", data, err)
	}
	if _, err := os.Lstat(retired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retired symlink still exists: %v", err)
	}
}

func TestInstallSystemdRefusesToRetireDirectoryAfterEnvironmentCutover(t *testing.T) {
	plan := nonRootInstallPlan(t)
	if err := os.MkdirAll(filepath.Join(plan.ConfigDir, "retired-secret"), 0o700); err != nil {
		t.Fatal(err)
	}
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	runner := &recordingCommandRunner{}
	if err := installActivatedFixtureError(t, plan, runner); err == nil || !strings.Contains(err.Error(), "directory") {
		t.Fatalf("InstallSystemd() error = %v", err)
	}
	assertInstalledFile(t, filepath.Join(plan.ConfigDir, "env"), "BIND=127.0.0.1\n", 0o640)
	if got := strings.Join(runner.calls, "\n"); !strings.Contains(got, "systemctl restart "+plan.UnitName) {
		t.Fatalf("retirement ran before activation:\n%s", got)
	}
}

func TestInstallSystemdPreservesRetiredFileWhenActivationFails(t *testing.T) {
	plan := nonRootInstallPlan(t)
	retired := prepareRetiredManagedFile(t, plan, "retired-secret")
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	runner := &recordingCommandRunner{fail: map[string]error{"systemctl restart " + plan.UnitName: errors.New("failed")}}
	if err := installActivatedFixtureError(t, plan, runner); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("installSystemdForIdentity() error = %v", err)
	}
	if _, err := os.Lstat(retired); err != nil {
		t.Fatalf("retired file was removed after failed activation: %v", err)
	}
}

func TestInstallSystemdPreservesRetiredFileWhenReadinessFails(t *testing.T) {
	plan := nonRootInstallPlan(t)
	retired := prepareRetiredManagedFile(t, plan, "retired-secret")
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	plan.ReadyCheck = func(context.Context) error { return errors.New("not ready") }
	plan.ReadyTimeout = 5 * time.Millisecond
	plan.ReadyInterval = time.Millisecond
	if err := installActivatedFixtureError(t, plan, &recordingCommandRunner{}); err == nil || !strings.Contains(err.Error(), "readiness") {
		t.Fatalf("installSystemdForIdentity() error = %v", err)
	}
	if _, err := os.Lstat(retired); err != nil {
		t.Fatalf("retired file was removed after failed readiness: %v", err)
	}
}

func TestSystemdInstallPlanValidation(t *testing.T) {
	valid := nonRootInstallPlan(t)
	tests := map[string]func(*SystemdInstallPlan){
		"unit name":      func(plan *SystemdInstallPlan) { plan.UnitName = "../bad.service" },
		"path traversal": func(plan *SystemdInstallPlan) { plan.ConfigDir += "/../config" },
		"path overlap": func(plan *SystemdInstallPlan) {
			plan.StateDir = plan.ConfigDir + "/state"
			plan.Unit.StateDir = plan.StateDir
		},
		"identity":        func(plan *SystemdInstallPlan) { plan.Unit.User = "other" },
		"directory":       func(plan *SystemdInstallPlan) { plan.Unit.ConfigDir = plan.StateDir },
		"activation":      func(plan *SystemdInstallPlan) { plan.NoStart = false },
		"file name":       func(plan *SystemdInstallPlan) { plan.Files[0].Name = "nested/env" },
		"file area":       func(plan *SystemdInstallPlan) { plan.Files[0].Area = "other" },
		"file owner":      func(plan *SystemdInstallPlan) { plan.Files[0].Owner = "other" },
		"file mode":       func(plan *SystemdInstallPlan) { plan.Files[0].Mode = 0o666 },
		"file unreadable": func(plan *SystemdInstallPlan) { plan.Files[0].Mode = 0o200 },
		"file oversized":  func(plan *SystemdInstallPlan) { plan.Files[0].Data = make([]byte, maxManagedFileBytes+1) },
		"environment owner": func(plan *SystemdInstallPlan) {
			plan.Files[0].Owner = ManagedFileOwnerService
		},
		"duplicate file": func(plan *SystemdInstallPlan) { plan.Files = append(plan.Files, plan.Files[0]) },
		"remove file name": func(plan *SystemdInstallPlan) {
			plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "nested/file"}}
		},
		"remove state file": func(plan *SystemdInstallPlan) {
			plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileState, Name: "state.json"}}
		},
		"write and remove file": func(plan *SystemdInstallPlan) {
			plan.RemoveFiles = []ManagedFileRef{{Area: plan.Files[0].Area, Name: plan.Files[0].Name}}
		},
		"remove environment": func(plan *SystemdInstallPlan) {
			plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "env"}}
		},
		"missing env": func(plan *SystemdInstallPlan) { plan.Unit.EnvironmentFile = filepath.Join(plan.ConfigDir, "missing") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			plan := cloneInstallPlan(valid)
			mutate(&plan)
			if err := plan.Validate(); err == nil {
				t.Fatalf("Validate(%s) error = nil", name)
			}
		})
	}
}

func TestSystemdInstallPlanRequiresReadinessForActivatedRetirement(t *testing.T) {
	plan := nonRootInstallPlan(t)
	plan.AllowNonRoot = false
	plan.NoStart = false
	plan.RemoveFiles = []ManagedFileRef{{Area: ManagedFileConfig, Name: "retired-secret"}}
	if err := plan.Validate(); err == nil || !strings.Contains(err.Error(), "readiness") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEnsureSystemAccountCreatesMissingAccount(t *testing.T) {
	runner := &recordingCommandRunner{fail: map[string]error{
		"getent group broker": errors.New("missing"),
		"id -u broker":        errors.New("missing"),
	}}
	plan := SystemdInstallPlan{User: "broker", Group: "broker", StateDir: "/var/lib/broker"}
	if err := ensureSystemAccount(context.Background(), runner, plan); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"getent group broker",
		"groupadd --system broker",
		"id -u broker",
		"useradd --system --gid broker --home-dir /var/lib/broker --shell /usr/sbin/nologin broker",
	}
	if got := strings.Join(runner.calls, "\n"); got != strings.Join(want, "\n") {
		t.Fatalf("runner calls:\n%s", got)
	}
}

func TestActivateSystemdUnit(t *testing.T) {
	runner := &recordingCommandRunner{}
	if err := activateSystemdUnit(context.Background(), runner, "broker.service"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(runner.calls, "\n"); got != "systemctl daemon-reload\nsystemctl enable broker.service\nsystemctl restart broker.service" {
		t.Fatalf("runner calls:\n%s", got)
	}
	runner.fail = map[string]error{"systemctl daemon-reload": errors.New("failed")}
	if err := activateSystemdUnit(context.Background(), runner, "broker.service"); err == nil {
		t.Fatal("activateSystemdUnit(failed reload) error = nil")
	}
	runner = &recordingCommandRunner{fail: map[string]error{"systemctl restart broker.service": errors.New("failed")}}
	if err := activateSystemdUnit(context.Background(), runner, "broker.service"); err == nil || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("activateSystemdUnit(failed restart) error = %v", err)
	}
}

func TestTrustedInstallDirectoryRejectsMutableAncestor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	if err := createTrustedInstallDirectoryPath(path, 0, false); err == nil || !strings.Contains(err.Error(), "mutable") {
		t.Fatalf("createTrustedInstallDirectoryPath() error = %v", err)
	}
}

func TestValidateInstallDirectoryComponentAllowsServiceOwnedFinalDirectory(t *testing.T) {
	directory, info, uid := installDirectoryFixture(t)
	if err := validateInstallDirectoryComponent(directory, info, true, uid, true); err != nil {
		t.Fatalf("service-owned final directory rejected: %v", err)
	}
}

func TestValidateInstallDirectoryComponentRejectsServiceOwnedAncestor(t *testing.T) {
	directory, info, uid := installDirectoryFixture(t)
	if err := validateInstallDirectoryComponent(directory, info, false, uid, true); err == nil || !strings.Contains(err.Error(), "untrusted owner") {
		t.Fatalf("service-owned ancestor error = %v", err)
	}
}

func TestValidateInstallDirectoryComponentRejectsRegularFile(t *testing.T) {
	directory, _, uid := installDirectoryFixture(t)
	file := filepath.Join(directory, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateInstallDirectoryComponent(file, fileInfo, true, uid, true); err == nil || !strings.Contains(err.Error(), "real directories") {
		t.Fatalf("regular-file component error = %v", err)
	}
}

func installDirectoryFixture(t *testing.T) (string, os.FileInfo, uint64) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil { // #nosec G302 -- this is a private directory, not a file.
		t.Fatal(err)
	}
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	uid, _, err := currentInstallIDs()
	if err != nil {
		t.Fatal(err)
	}
	return directory, info, uid
}

func TestInstallChownIDs(t *testing.T) {
	uid, gid, err := installChownIDs(1000, 1001)
	if err != nil || uid != 1000 || gid != 1001 {
		t.Fatalf("installChownIDs(valid) = %d, %d, %v", uid, gid, err)
	}
	tooLarge := uint64(^uint(0)>>1) + 1
	if _, _, err := installChownIDs(tooLarge, 0); err == nil {
		t.Fatal("installChownIDs(large uid) error = nil")
	}
	if _, _, err := installChownIDs(0, tooLarge); err == nil {
		t.Fatal("installChownIDs(large gid) error = nil")
	}
}

func nonRootInstallPlan(t *testing.T) SystemdInstallPlan {
	t.Helper()
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	stateDir := filepath.Join(root, "state")
	systemdDir := filepath.Join(root, "systemd")
	return SystemdInstallPlan{
		User: account.Username, Group: group.Name,
		ConfigDir: configDir, StateDir: stateDir, SystemdDir: systemdDir,
		UnitName: "test-broker.service", NoStart: true, AllowNonRoot: true,
		Files: []ManagedFile{
			{Area: ManagedFileConfig, Name: "env", Data: []byte("BIND=127.0.0.1\n"), Mode: 0o640, Owner: ManagedFileOwnerRoot},
			{Area: ManagedFileConfig, Name: "secret", Data: []byte("opaque-secret"), Mode: 0o600, Owner: ManagedFileOwnerService},
			{Area: ManagedFileState, Name: "grants.json", Data: []byte("{}\n"), Mode: 0o600, Owner: ManagedFileOwnerService},
		},
		Unit: SystemdUnit{
			Description: "test broker", User: account.Username, Group: group.Name,
			EnvironmentFile: filepath.Join(configDir, "env"), ExecStart: "/usr/bin/test",
			StateDir: stateDir, ConfigDir: configDir,
		},
	}
}

func cloneInstallPlan(plan SystemdInstallPlan) SystemdInstallPlan {
	clone := plan
	clone.Files = append([]ManagedFile(nil), plan.Files...)
	clone.RemoveFiles = append([]ManagedFileRef(nil), plan.RemoveFiles...)
	for index := range clone.Files {
		clone.Files[index].Data = append([]byte(nil), clone.Files[index].Data...)
	}
	return clone
}

func prepareRetiredManagedFile(t *testing.T, plan SystemdInstallPlan, name string) string {
	t.Helper()
	if err := os.MkdirAll(plan.ConfigDir, 0o750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(plan.ConfigDir, name)
	if err := os.WriteFile(path, []byte("old-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func installActivatedFixture(t *testing.T, plan SystemdInstallPlan, runner CommandRunner) {
	t.Helper()
	if err := installActivatedFixtureError(t, plan, runner); err != nil {
		t.Fatal(err)
	}
}

func installActivatedFixtureError(t *testing.T, plan SystemdInstallPlan, runner CommandRunner) error {
	t.Helper()
	uid, gid, err := currentInstallIDs()
	if err != nil {
		t.Fatal(err)
	}
	plan.NoStart = false
	if plan.ReadyCheck == nil {
		plan.ReadyCheck = func(context.Context) error { return nil }
	}
	return installSystemdForIdentity(context.Background(), runner, plan, uid, gid)
}

func assertInstalledFile(t *testing.T, path string, body string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reads its private fixture path.
	if err != nil || string(data) != body {
		t.Fatalf("file %s = %q, err=%v", path, data, err)
	}
	assertMode(t, path, mode)
}

func assertMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("mode(%s) = %o, want %o", path, info.Mode().Perm(), mode)
	}
}

type recordingCommandRunner struct {
	calls []string
	fail  map[string]error
}

func (runner *recordingCommandRunner) Run(_ context.Context, name string, args ...string) error {
	call := strings.Join(append([]string{name}, args...), " ")
	runner.calls = append(runner.calls, call)
	return runner.fail[call]
}
