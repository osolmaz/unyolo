//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// InstallLaunchd installs one system LaunchDaemon from a validated typed plan.
func InstallLaunchd(ctx context.Context, plan LaunchdInstallPlan) error {
	if err := validateLaunchdExecution(plan); err != nil {
		return err
	}
	runner := plan.Runner
	if runner == nil {
		runner = launchdCommandRunner{}
	}
	if err := installLaunchdPayload(ctx, runner, plan); err != nil {
		return err
	}
	return startLaunchdInstallation(ctx, runner, plan)
}

func validateLaunchdExecution(plan LaunchdInstallPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if os.Geteuid() != 0 && !plan.AllowNonRoot {
		return errors.New("launchd installation must run as root")
	}
	return nil
}

func installLaunchdPayload(ctx context.Context, runner CommandRunner, plan LaunchdInstallPlan) error {
	if err := ensureLaunchdAccounts(ctx, runner, plan); err != nil {
		return err
	}
	uid, gid, err := launchdIdentityIDs(plan.User, plan.Group)
	if err != nil {
		return err
	}
	if err := prepareLaunchdDirectories(plan, uid, gid); err != nil {
		return err
	}
	if err := writeLaunchdInstallation(plan, uid, gid); err != nil {
		return err
	}
	return nil
}

func startLaunchdInstallation(ctx context.Context, runner CommandRunner, plan LaunchdInstallPlan) error {
	if plan.NoStart {
		return nil
	}
	if err := bootstrapLaunchd(ctx, runner, plan); err != nil {
		return err
	}
	if err := waitForLaunchdReady(ctx, plan); err != nil {
		return err
	}
	return removeLaunchdManagedFiles(plan)
}

type launchdCommandRunner struct{}

func (launchdCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run() // #nosec G204 -- names and arguments are fixed setup primitives.
}

func ensureLaunchdAccounts(ctx context.Context, runner CommandRunner, plan LaunchdInstallPlan) error {
	if runner.Run(ctx, "id", "-u", plan.User) != nil {
		return fmt.Errorf("launchd service account %q must exist before installation", plan.User)
	}
	if runner.Run(ctx, "dscl", ".", "-read", "/Groups/"+plan.Group) != nil {
		return fmt.Errorf("launchd service group %q must exist before installation", plan.Group)
	}
	for _, group := range plan.AdditionalGroups {
		if runner.Run(ctx, "dscl", ".", "-read", "/Groups/"+group) != nil {
			if err := runner.Run(ctx, "dseditgroup", "-o", "create", group); err != nil {
				return fmt.Errorf("create launchd access group %q: %w", group, err)
			}
		}
	}
	for group, members := range plan.GroupMembers {
		for _, member := range members {
			if err := runner.Run(ctx, "dseditgroup", "-o", "edit", "-a", member, "-t", "user", group); err != nil {
				return fmt.Errorf("add %q to launchd access group %q: %w", member, group, err)
			}
		}
	}
	return nil
}

func launchdIdentityIDs(userName, groupName string) (int, int, error) {
	account, err := user.Lookup(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("look up launchd user: %w", err)
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("look up launchd group: %w", err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(group.Gid)
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 {
		return 0, 0, errors.New("launchd account has invalid numeric identity")
	}
	return uid, gid, nil
}

func prepareLaunchdDirectories(plan LaunchdInstallPlan, uid, gid int) error {
	for _, directory := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{
		{path: plan.ConfigDir, mode: 0o750, uid: 0, gid: gid},
		{path: plan.StateDir, mode: 0o750, uid: uid, gid: gid},
	} {
		if plan.AllowNonRoot {
			directory.uid, directory.gid = os.Geteuid(), os.Getegid()
		}
		if err := ensureLaunchdDirectory(directory.path, directory.mode, directory.uid, directory.gid, plan.AllowNonRoot); err != nil {
			return err
		}
	}
	for _, socket := range plan.Unit.Sockets {
		groupID, err := launchdGroupID(socket.Group, plan.AllowNonRoot)
		if err != nil {
			return err
		}
		if err := ensureLaunchdDirectory(filepath.Dir(socket.Path), socket.DirectoryMode, 0, groupID, plan.AllowNonRoot); err != nil {
			return err
		}
	}
	for _, directory := range plan.RuntimeDirectories {
		ownerID, groupID, err := launchdDirectoryIDs(directory, plan.AllowNonRoot)
		if err != nil {
			return err
		}
		if err := ensureLaunchdDirectory(directory.Path, directory.Mode, ownerID, groupID, plan.AllowNonRoot); err != nil {
			return err
		}
	}
	return nil
}

func launchdDirectoryIDs(directory LaunchdDirectory, preview bool) (int, int, error) {
	if preview {
		return os.Geteuid(), os.Getegid(), nil
	}
	account, err := user.Lookup(directory.Owner)
	if err != nil {
		return 0, 0, fmt.Errorf("look up launchd runtime owner %q: %w", directory.Owner, err)
	}
	group, err := user.LookupGroup(directory.Group)
	if err != nil {
		return 0, 0, fmt.Errorf("look up launchd runtime group %q: %w", directory.Group, err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(group.Gid)
	if uidErr != nil || gidErr != nil || uid < 0 || gid < 0 {
		return 0, 0, errors.New("launchd runtime directory identity is invalid")
	}
	return uid, gid, nil
}

func launchdGroupID(groupName string, preview bool) (int, error) {
	if preview {
		return os.Getegid(), nil
	}
	group, err := user.LookupGroup(groupName)
	if err != nil {
		return 0, fmt.Errorf("look up launchd socket group %q: %w", groupName, err)
	}
	gid, err := strconv.Atoi(group.Gid)
	if err != nil || gid < 0 {
		return 0, fmt.Errorf("launchd socket group %q has invalid gid", groupName)
	}
	return gid, nil
}

func ensureLaunchdDirectory(path string, mode os.FileMode, uid, gid int, preview bool) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create launchd directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("launchd path is not a trusted directory: %s", path)
	}
	if !preview {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && int(stat.Uid) != uid {
			return fmt.Errorf("launchd directory has unexpected owner: %s", path)
		}
		if err := os.Chown(path, uid, gid); err != nil {
			return err
		}
	}
	return os.Chmod(path, mode)
}

func writeLaunchdInstallation(plan LaunchdInstallPlan, uid, gid int) error {
	for _, file := range plan.Files {
		path := launchdManagedPath(plan, file.Area, file.Name)
		owner := 0
		if file.Owner == ManagedFileOwnerService {
			owner = uid
		}
		if plan.AllowNonRoot {
			owner, gid = os.Geteuid(), os.Getegid()
		}
		if err := writeAtomicLaunchdFile(path, file.Data, file.Mode, owner, gid, plan.AllowNonRoot); err != nil {
			return fmt.Errorf("write launchd managed file %s: %w", path, err)
		}
	}
	body, err := RenderLaunchd(plan.Unit)
	if err != nil {
		return err
	}
	plistUID, plistGID := 0, 0
	if plan.AllowNonRoot {
		plistUID, plistGID = os.Geteuid(), os.Getegid()
	}
	return writeAtomicLaunchdFile(filepath.Join(plan.LaunchdDir, plan.PlistName), []byte(body), 0o644, plistUID, plistGID, plan.AllowNonRoot)
}

func writeAtomicLaunchdFile(path string, data []byte, mode os.FileMode, uid, gid int, preview bool) error {
	parent := filepath.Dir(path)
	temporary, err := os.CreateTemp(parent, ".brokerkit-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() { _ = os.Remove(temporaryPath) }()
	steps := []func() error{
		func() error { _, writeErr := temporary.Write(data); return writeErr },
		func() error {
			if preview {
				return nil
			}
			return temporary.Chown(uid, gid)
		},
		func() error { return temporary.Chmod(mode) }, temporary.Sync, temporary.Close,
		func() error { return os.Rename(temporaryPath, path) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			_ = temporary.Close()
			return err
		}
	}
	return syncLaunchdDirectory(parent)
}

func syncLaunchdDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- path is a validated install root or its direct parent.
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	return directory.Sync()
}

func bootstrapLaunchd(ctx context.Context, runner CommandRunner, plan LaunchdInstallPlan) error {
	target := "system/" + plan.Unit.Label
	plist := filepath.Join(plan.LaunchdDir, plan.PlistName)
	_ = runner.Run(ctx, "launchctl", "bootout", target)
	if err := runner.Run(ctx, "launchctl", "bootstrap", "system", plist); err != nil {
		return fmt.Errorf("launchctl bootstrap: %w", err)
	}
	if err := runner.Run(ctx, "launchctl", "kickstart", "-k", target); err != nil {
		return fmt.Errorf("launchctl kickstart: %w", err)
	}
	return nil
}

func waitForLaunchdReady(ctx context.Context, plan LaunchdInstallPlan) error {
	if plan.ReadyCheck == nil {
		return nil
	}
	readyContext, cancel := context.WithTimeout(ctx, durationOrLaunchd(plan.ReadyTimeout, defaultReadinessTimeout))
	defer cancel()
	ticker := time.NewTicker(durationOrLaunchd(plan.ReadyInterval, defaultReadinessInterval))
	defer ticker.Stop()
	for {
		if err := plan.ReadyCheck(readyContext); err == nil && readyContext.Err() == nil {
			return nil
		}
		select {
		case <-readyContext.Done():
			return errServiceReadinessFailed
		case <-ticker.C:
		}
	}
}

func durationOrLaunchd(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func removeLaunchdManagedFiles(plan LaunchdInstallPlan) error {
	for _, file := range plan.RemoveFiles {
		path := launchdManagedPath(plan, file.Area, file.Name)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse to retire unsafe launchd managed path: %s", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}

func launchdManagedPath(plan LaunchdInstallPlan, area ManagedFileArea, name string) string {
	if area == ManagedFileState {
		return filepath.Join(plan.StateDir, name)
	}
	return filepath.Join(plan.ConfigDir, name)
}
