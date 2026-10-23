package bundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// replaceComponentState archives a component's previous state before a state
// format change. It archives only the declared state files when the component
// lists them, and the whole state directory otherwise.
func replaceComponentState(component Component, backup string) error {
	if len(component.StateFiles) == 0 {
		return replaceStateDirectory(component.StateDir, backup)
	}
	return replaceStateFiles(component.StateDir, component.StateFiles, backup)
}

// restoreComponentState undoes replaceComponentState.
func restoreComponentState(component Component, backup string) error {
	if len(component.StateFiles) == 0 {
		return restoreStateDirectory(component.StateDir, backup)
	}
	return restoreStateFiles(component.StateDir, component.StateFiles, backup)
}

// replaceStateFiles moves the listed files from stateDir into a new backup
// directory and keeps every other file in stateDir.
func replaceStateFiles(stateDir string, names []string, backup string) error {
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		return errors.New("state replacement backup already exists or cannot be inspected")
	}
	info, err := os.Stat(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(stateDir, 0o700)
	}
	if err != nil || !info.IsDir() {
		return errors.New("state replacement source is not a directory")
	}
	if err := os.Mkdir(backup, 0o700); err != nil {
		return fmt.Errorf("create state backup: %w", err)
	}
	for _, name := range names {
		if err := os.Rename(filepath.Join(stateDir, name), filepath.Join(backup, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.Join(fmt.Errorf("archive state file %s: %w", name, err), restoreStateFiles(stateDir, names, backup))
		}
	}
	return errors.Join(syncDirectory(stateDir), syncDirectory(filepath.Dir(backup)))
}

// restoreStateFiles moves archived state files back over the ones that the
// new release created, and removes the backup directory.
func restoreStateFiles(stateDir string, names []string, backup string) error {
	if _, err := os.Lstat(backup); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	for _, name := range names {
		archived := filepath.Join(backup, name)
		if _, err := os.Lstat(archived); errors.Is(err, os.ErrNotExist) {
			if err := os.Remove(filepath.Join(stateDir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			continue
		}
		if err := os.Rename(archived, filepath.Join(stateDir, name)); err != nil {
			return fmt.Errorf("restore state file %s: %w", name, err)
		}
	}
	return os.Remove(backup)
}
