//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

type installTarget struct {
	root *os.Root
	name string
}

type installFileSnapshot struct {
	installTarget
	existed    bool
	restorable bool
	symlink    bool
	linkTarget string
	data       []byte
	mode       os.FileMode
	uid        uint64
	gid        uint64
}

type systemdInstallSnapshot struct {
	files   []installFileSnapshot
	hadUnit bool
	preview bool
}

func captureSystemdInstall(roots installRoots, plan SystemdInstallPlan) (*systemdInstallSnapshot, error) {
	targets := systemdInstallTargets(roots, plan)
	if len(targets) > maxInstallRollbackFiles {
		return nil, errors.New("systemd install exceeds rollback file limit")
	}
	snapshot := &systemdInstallSnapshot{files: make([]installFileSnapshot, 0, len(targets)), preview: plan.AllowNonRoot}
	total := 0
	for _, target := range targets {
		file, size, err := captureInstallFile(target)
		if err != nil {
			snapshot.clear()
			return nil, err
		}
		total += size
		if total > maxInstallRollbackBytes {
			snapshot.clear()
			return nil, errors.New("systemd install exceeds rollback byte limit")
		}
		snapshot.files = append(snapshot.files, file)
	}
	snapshot.hadUnit = snapshot.files[len(plan.Files)].restorable
	return snapshot, nil
}

func systemdInstallTargets(roots installRoots, plan SystemdInstallPlan) []installTarget {
	targets := make([]installTarget, 0, len(plan.Files)+1+len(plan.SocketUnits))
	for _, file := range plan.Files {
		targets = append(targets, installTarget{root: managedFileRoot(roots, file.Area), name: file.Name})
	}
	targets = append(targets, installTarget{root: roots.systemd, name: plan.UnitName})
	for _, socket := range plan.SocketUnits {
		targets = append(targets, installTarget{root: roots.systemd, name: socket.UnitName})
	}
	return targets
}

func captureInstallFile(target installTarget) (installFileSnapshot, int, error) {
	snapshot := installFileSnapshot{installTarget: target}
	info, err := target.root.Lstat(target.name)
	if errors.Is(err, os.ErrNotExist) {
		return snapshot, 0, nil
	}
	if err != nil {
		return snapshot, 0, fmt.Errorf("inspect previous managed file %s: %w", target.name, err)
	}
	snapshot.existed = true
	if info.Mode()&os.ModeSymlink != 0 {
		return captureInstallSymlink(snapshot)
	}
	if !info.Mode().IsRegular() {
		return snapshot, 0, nil
	}
	return captureRegularInstallFile(snapshot, info)
}

func captureInstallSymlink(snapshot installFileSnapshot) (installFileSnapshot, int, error) {
	linkTarget, err := snapshot.root.Readlink(snapshot.name)
	if err != nil {
		return snapshot, 0, fmt.Errorf("read previous managed symlink %s: %w", snapshot.name, err)
	}
	snapshot.symlink, snapshot.linkTarget = true, linkTarget
	return snapshot, 0, nil
}

func captureRegularInstallFile(snapshot installFileSnapshot, info os.FileInfo) (installFileSnapshot, int, error) {
	if info.Size() > maxManagedFileBytes {
		return snapshot, 0, fmt.Errorf("previous managed file %s exceeds rollback limit", snapshot.name)
	}
	data, err := readInstallFile(snapshot.installTarget, info.Size())
	if err != nil {
		return snapshot, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		clearSecretBytes(data)
		return snapshot, 0, fmt.Errorf("previous managed file ownership is unavailable: %s", snapshot.name)
	}
	snapshot.restorable = true
	snapshot.data, snapshot.mode = data, info.Mode().Perm()
	snapshot.uid, snapshot.gid = uint64(stat.Uid), uint64(stat.Gid)
	return snapshot, len(data), nil
}

func readInstallFile(target installTarget, size int64) ([]byte, error) {
	file, err := target.root.Open(target.name)
	if err != nil {
		return nil, fmt.Errorf("open previous managed file %s: %w", target.name, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, size+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != size {
		clearSecretBytes(data)
		return nil, fmt.Errorf("read previous managed file %s: %w", target.name, errors.Join(readErr, closeErr))
	}
	return data, nil
}

func (s *systemdInstallSnapshot) rollback(ctx context.Context, runner CommandRunner, plan SystemdInstallPlan) error {
	restoreErr := s.restore()
	if !s.hadUnit {
		return restoreErr
	}
	units := plan.ActivationUnits
	if len(units) == 0 {
		units = []string{plan.UnitName}
	}
	activateErr := activateSystemdUnits(ctx, runner, units)
	return errors.Join(restoreErr, activateErr)
}

func (s *systemdInstallSnapshot) restore() error {
	var restoreErr error
	for index := len(s.files) - 1; index >= 0; index-- {
		restoreErr = errors.Join(restoreErr, restoreInstallFile(s.files[index], s.preview))
	}
	return restoreErr
}

func restoreInstallFile(file installFileSnapshot, preview bool) error {
	if file.restorable {
		return writeAtomicInstallFile(file.root, file.name, file.data, file.mode, file.uid, file.gid, preview)
	}
	if file.symlink {
		return restoreInstallSymlink(file)
	}
	if file.existed {
		return nil
	}
	return removeCreatedInstallFile(file)
}

func restoreInstallSymlink(file installFileSnapshot) error {
	info, err := file.root.Lstat(file.name)
	if err == nil && !info.IsDir() {
		err = file.root.Remove(file.name)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return errors.Join(file.root.Symlink(file.linkTarget, file.name), syncInstallRoot(file.root))
}

func removeCreatedInstallFile(file installFileSnapshot) error {
	info, err := file.root.Lstat(file.name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("refuse to remove rollback directory: %s", file.name)
	}
	return errors.Join(file.root.Remove(file.name), syncInstallRoot(file.root))
}

func (s *systemdInstallSnapshot) clear() {
	for index := range s.files {
		clearSecretBytes(s.files[index].data)
	}
}
