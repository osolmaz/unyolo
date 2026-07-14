//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type launchdFileSnapshot struct {
	path       string
	existed    bool
	restorable bool
	symlink    bool
	linkTarget string
	data       []byte
	mode       os.FileMode
	uid        int
	gid        int
}

type launchdInstallSnapshot struct {
	files    []launchdFileSnapshot
	hadPlist bool
	preview  bool
}

func captureLaunchdInstall(plan LaunchdInstallPlan) (*launchdInstallSnapshot, error) {
	paths := make([]string, 0, len(plan.Files)+1)
	for _, file := range plan.Files {
		paths = append(paths, launchdManagedPath(plan, file.Area, file.Name))
	}
	paths = append(paths, filepath.Join(plan.LaunchdDir, plan.PlistName))
	if len(paths) > maxInstallRollbackFiles {
		return nil, errors.New("launchd install exceeds rollback file limit")
	}
	snapshot := &launchdInstallSnapshot{files: make([]launchdFileSnapshot, 0, len(paths)), preview: plan.AllowNonRoot}
	total := 0
	for _, path := range paths {
		file, size, err := captureLaunchdFile(path)
		if err != nil {
			snapshot.clear()
			return nil, err
		}
		total += size
		if total > maxInstallRollbackBytes {
			snapshot.clear()
			return nil, errors.New("launchd install exceeds rollback byte limit")
		}
		snapshot.files = append(snapshot.files, file)
	}
	snapshot.hadPlist = snapshot.files[len(plan.Files)].restorable
	return snapshot, nil
}

func captureLaunchdFile(path string) (launchdFileSnapshot, int, error) {
	snapshot := launchdFileSnapshot{path: path}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, 0, nil
	}
	if err != nil {
		return snapshot, 0, fmt.Errorf("inspect previous managed file %s: %w", path, err)
	}
	snapshot.existed = true
	if info.Mode()&os.ModeSymlink != 0 {
		return captureLaunchdSymlink(snapshot)
	}
	if !info.Mode().IsRegular() {
		return snapshot, 0, nil
	}
	return captureRegularLaunchdFile(snapshot, info)
}

func captureLaunchdSymlink(snapshot launchdFileSnapshot) (launchdFileSnapshot, int, error) {
	target, err := os.Readlink(snapshot.path)
	if err != nil {
		return snapshot, 0, fmt.Errorf("read previous managed symlink %s: %w", snapshot.path, err)
	}
	snapshot.symlink, snapshot.linkTarget = true, target
	return snapshot, 0, nil
}

func captureRegularLaunchdFile(snapshot launchdFileSnapshot, info os.FileInfo) (launchdFileSnapshot, int, error) {
	if info.Size() > maxManagedFileBytes {
		return snapshot, 0, fmt.Errorf("previous managed file %s exceeds rollback limit", snapshot.path)
	}
	file, err := os.Open(snapshot.path) // #nosec G304 -- path is a validated install target.
	if err != nil {
		return snapshot, 0, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, info.Size()+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != info.Size() {
		clearSecretBytes(data)
		return snapshot, 0, fmt.Errorf("read previous managed file %s: %w", snapshot.path, errors.Join(readErr, closeErr))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		clearSecretBytes(data)
		return snapshot, 0, fmt.Errorf("previous managed file ownership is unavailable: %s", snapshot.path)
	}
	snapshot.restorable, snapshot.data, snapshot.mode = true, data, info.Mode().Perm()
	snapshot.uid, snapshot.gid = int(stat.Uid), int(stat.Gid)
	return snapshot, len(data), nil
}

func (s *launchdInstallSnapshot) rollback(ctx context.Context, runner CommandRunner, plan LaunchdInstallPlan) error {
	restoreErr := s.restore()
	if !s.hadPlist {
		return restoreErr
	}
	return errors.Join(restoreErr, bootstrapLaunchd(ctx, runner, plan))
}

func (s *launchdInstallSnapshot) restore() error {
	var restoreErr error
	for index := len(s.files) - 1; index >= 0; index-- {
		restoreErr = errors.Join(restoreErr, restoreLaunchdFile(s.files[index], s.preview))
	}
	return restoreErr
}

func restoreLaunchdFile(file launchdFileSnapshot, preview bool) error {
	if file.restorable {
		return writeAtomicLaunchdFile(file.path, file.data, file.mode, file.uid, file.gid, preview)
	}
	if file.symlink {
		return restoreLaunchdSymlink(file)
	}
	if file.existed {
		return nil
	}
	return removeCreatedLaunchdFile(file.path)
}

func restoreLaunchdSymlink(file launchdFileSnapshot) error {
	info, err := os.Lstat(file.path)
	if err == nil && !info.IsDir() {
		err = os.Remove(file.path)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return errors.Join(os.Symlink(file.linkTarget, file.path), syncLaunchdDirectory(filepath.Dir(file.path)))
}

func removeCreatedLaunchdFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("refuse to remove rollback directory: %s", path)
	}
	return errors.Join(os.Remove(path), syncLaunchdDirectory(filepath.Dir(path)))
}

func (s *launchdInstallSnapshot) clear() {
	for index := range s.files {
		clearSecretBytes(s.files[index].data)
	}
}
