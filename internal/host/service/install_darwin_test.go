//go:build darwin

package service

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

type launchdTestRunner struct{}

func (launchdTestRunner) Run(context.Context, string, ...string) error { return nil }

func TestInstallLaunchdPreview(t *testing.T) {
	account, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(account.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	plan := launchdInstallFixture()
	plan.User, plan.Group = account.Username, group.Name
	plan.Unit.UserName, plan.Unit.GroupName = account.Username, group.Name
	plan.Unit.ProgramArguments = []string{"/usr/bin/true"}
	plan.Unit.Sockets[0].Owner, plan.Unit.Sockets[0].Group = account.Username, group.Name
	plan.Unit.Sockets[0].Path = filepath.Join(root, "run", "agent.sock")
	plan.RuntimeDirectories[0].Path = filepath.Join(root, "private-run")
	plan.RuntimeDirectories[0].Owner, plan.RuntimeDirectories[0].Group = account.Username, group.Name
	plan.ConfigDir, plan.StateDir = filepath.Join(root, "config"), filepath.Join(root, "state")
	plan.LaunchdDir = filepath.Join(root, "launchd")
	plan.AdditionalGroups, plan.GroupMembers = nil, nil
	plan.Runner = launchdTestRunner{}
	if err := os.MkdirAll(plan.LaunchdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := InstallLaunchd(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(plan.ConfigDir, "secret"), filepath.Join(plan.LaunchdDir, plan.PlistName)} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("installed file %s: %v", path, err)
		}
	}
}

func TestLaunchdInstallSnapshotRestoresReplacedCredentials(t *testing.T) {
	root := t.TempDir()
	plan := launchdInstallFixture()
	plan.ConfigDir, plan.StateDir, plan.LaunchdDir = filepath.Join(root, "config"), filepath.Join(root, "state"), filepath.Join(root, "launchd")
	for _, directory := range []string{plan.ConfigDir, plan.StateDir, plan.LaunchdDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secretPath := filepath.Join(plan.ConfigDir, "secret")
	plistPath := filepath.Join(plan.LaunchdDir, plan.PlistName)
	for path, body := range map[string]string{secretPath: "old-secret", plistPath: "old-plist"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := captureLaunchdInstall(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.clear()
	if err := writeAtomicLaunchdFile(secretPath, []byte("new-secret"), 0o600, os.Geteuid(), os.Getegid(), true); err != nil {
		t.Fatal(err)
	}
	if err := writeAtomicLaunchdFile(plistPath, []byte("new-plist"), 0o600, os.Geteuid(), os.Getegid(), true); err != nil {
		t.Fatal(err)
	}
	if err := snapshot.restore(); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{secretPath: "old-secret", plistPath: "old-plist"} {
		data, err := os.ReadFile(path) // #nosec G304 -- controlled test fixture.
		if err != nil || string(data) != want {
			t.Fatalf("restored %s = %q, %v; want %q", path, data, err, want)
		}
	}
}
