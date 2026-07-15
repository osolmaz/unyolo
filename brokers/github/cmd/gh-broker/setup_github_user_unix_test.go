//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func assertSetupStateOwnership(t *testing.T, stateDir string, paths ...string) {
	t.Helper()
	owner := setupPathOwner(t, stateDir)
	for _, path := range paths {
		if got := setupPathOwner(t, path); got != owner {
			t.Fatalf("%s owner = %+v, want %+v", path, got, owner)
		}
	}
}

func TestGitHubUserSetupRequiresExistingStateDirectory(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	owner, err := githubUserSetupStateOwner(stateDir)
	if err != nil || owner != setupPathOwner(t, stateDir) {
		t.Fatalf("trusted state owner = %+v, %v", owner, err)
	}
	if err := preserveGitHubUserStateOwnership(t.TempDir() + "/missing"); err == nil {
		t.Fatal("missing state directory accepted")
	}
	unsafe := t.TempDir()
	if err := os.Chmod(unsafe, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := preserveGitHubUserStateOwnership(unsafe); err == nil {
		t.Fatal("group-writable state directory accepted")
	}
	link := stateDir + "-link"
	if err := os.Symlink(stateDir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := githubUserSetupStateOwner(link); err == nil {
		t.Fatal("symlink state directory accepted")
	}
}

func TestGitHubUserPathOwnerRejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	owner, exists, err := githubUserPathOwner(dir + "/missing")
	if err != nil || exists || owner != (githubUserStateOwner{}) {
		t.Fatalf("missing path owner = %+v, %t, %v", owner, exists, err)
	}
	link := dir + "/link"
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := githubUserPathOwner(link); err == nil {
		t.Fatal("symlink credential path accepted")
	}
}

func TestPreserveGitHubUserPathOwnershipRepairsMismatch(t *testing.T) {
	path := t.TempDir()
	current := setupPathOwner(t, path)
	want := githubUserStateOwner{uid: current.uid + 1, gid: current.gid + 1}
	called := false
	err := preserveGitHubUserPathOwnershipWith(path, want, func(gotPath string, uid int, gid int) error {
		called = true
		if gotPath != path || uid != int(want.uid) || gid != int(want.gid) {
			t.Fatalf("chown = %q, %d, %d", gotPath, uid, gid)
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("preserve ownership = called %t, %v", called, err)
	}
	if err := preserveGitHubUserPathOwnershipWith(path, want, func(string, int, int) error {
		return errors.New("denied")
	}); err == nil {
		t.Fatal("chown failure was ignored")
	}
}

func setupPathOwner(t *testing.T, path string) githubUserStateOwner {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s ownership is unavailable", path)
	}
	return githubUserStateOwner{uid: stat.Uid, gid: stat.Gid}
}
