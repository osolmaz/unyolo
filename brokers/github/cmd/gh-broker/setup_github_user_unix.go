//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/osolmaz/brokerkit/brokers/github/internal/githubauth"
)

type githubUserStateOwner struct {
	uid uint32
	gid uint32
}

func preserveGitHubUserStateOwnership(stateDir string) error {
	owner, err := githubUserSetupStateOwner(stateDir)
	if err != nil {
		return err
	}
	storeRoot, err := githubauth.UserCredentialStorePath(stateDir)
	if err != nil {
		return err
	}
	slotsPath := filepath.Join(storeRoot, "credential-slots")
	paths := []string{filepath.Dir(storeRoot), storeRoot, filepath.Join(storeRoot, "credential-slots.key"), slotsPath}
	entries, readErr := os.ReadDir(slotsPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		return errors.New("inspect GitHub user credential store")
	}
	for _, entry := range entries {
		paths = append(paths, filepath.Join(slotsPath, entry.Name()))
	}
	for _, path := range paths {
		if err := preserveGitHubUserPathOwnership(path, owner); err != nil {
			return err
		}
	}
	return nil
}

func githubUserSetupStateOwner(stateDir string) (githubUserStateOwner, error) {
	info, err := os.Lstat(stateDir) // #nosec G703 -- operator-selected local service state path.
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return githubUserStateOwner{}, errors.New("GitHub user setup requires an existing trusted state directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return githubUserStateOwner{}, errors.New("GitHub user state directory ownership is unavailable")
	}
	return githubUserStateOwner{uid: stat.Uid, gid: stat.Gid}, nil
}

func preserveGitHubUserPathOwnership(path string, owner githubUserStateOwner) error {
	return preserveGitHubUserPathOwnershipWith(path, owner, os.Chown)
}

func preserveGitHubUserPathOwnershipWith(path string, owner githubUserStateOwner, chown func(string, int, int) error) error {
	current, exists, err := githubUserPathOwner(path)
	if err != nil || !exists {
		return err
	}
	if current == owner {
		return nil
	}
	if err := chown(path, int(owner.uid), int(owner.gid)); err != nil { // #nosec G115 -- kernel-provided uid/gid fields.
		return fmt.Errorf("preserve GitHub user credential store ownership: %w", err)
	}
	return nil
}

func githubUserPathOwner(path string) (githubUserStateOwner, bool, error) {
	info, err := os.Lstat(path) // #nosec G703 -- fixed children of the trusted service state path.
	if os.IsNotExist(err) {
		return githubUserStateOwner{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
		return githubUserStateOwner{}, false, errors.New("GitHub user credential store contains an unsafe path")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return githubUserStateOwner{}, false, errors.New("GitHub user credential ownership is unavailable")
	}
	return githubUserStateOwner{uid: stat.Uid, gid: stat.Gid}, true, nil
}
