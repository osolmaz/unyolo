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
