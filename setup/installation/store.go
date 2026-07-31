package installation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	files "github.com/osolmaz/unyolo/internal/storage/files"
)

const (
	EntryFilename = "installation.json"

	// Phase values persisted by the recoverable publication transaction.
	phasePublishing = "publishing"
	phaseApplying   = "applying"
	phaseCommitted  = "committed"
)

type Store struct {
	Root string
}

type marker struct {
	APIVersion string `json:"api_version"`
	Name       string `json:"name"`
	Phase      string `json:"phase"`
	Backup     string `json:"backup,omitempty"`
}

func DefaultRoot() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(root) {
		return "", errors.New("user configuration directory is unavailable")
	}
	return filepath.Join(root, "unyolo", "installations"), nil
}

func (store Store) Directory(name string) (string, error) {
	if !validName(name) || !filepath.IsAbs(store.Root) || filepath.Clean(store.Root) != store.Root {
		return "", errors.New("installation store path is invalid")
	}
	return filepath.Join(store.Root, name), nil
}

func (store Store) Load(name string) (Installation, error) {
	directory, err := store.Directory(name)
	if err != nil {
		return Installation{}, err
	}
	data, err := os.ReadFile(filepath.Join(directory, EntryFilename)) // #nosec G304 -- name and root are validated.
	if err != nil {
		return Installation{}, err
	}
	return Decode(data)
}

// Publish installs desired and generated state before apply and restores the previous state on failure.
func (store Store) Publish(value Installation, generatedRoot string, apply func(string) error) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if apply == nil || !filepath.IsAbs(generatedRoot) || filepath.Clean(generatedRoot) != generatedRoot {
		return errors.New("installation publication input is invalid")
	}
	current, err := store.Directory(value.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(store.Root, 0o700); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(store.Root, ".installation-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	data, err := value.Canonical()
	if err != nil {
		return err
	}
	if err := files.WriteFileAtomic(filepath.Join(staging, EntryFilename), data, 0o600); err != nil {
		return err
	}
	if err := copyTree(generatedRoot, filepath.Join(staging, "generated")); err != nil {
		return err
	}
	backup := ""
	state := marker{APIVersion: APIVersion, Name: value.Name, Phase: phasePublishing}
	markerPath := filepath.Join(store.Root, ".transaction.json")
	if _, statErr := os.Lstat(current); statErr == nil {
		backup = current + fmt.Sprintf(".backup-%d", time.Now().UnixNano())
		if err := os.Rename(current, backup); err != nil {
			return err
		}
		state.Backup = backup
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	if err := files.WriteJSONAtomic(markerPath, state, 0o600); err != nil {
		_ = restoreDirectory(current, backup)
		return err
	}
	if err := os.Rename(staging, current); err != nil {
		_ = restoreDirectory(current, backup)
		_ = os.Remove(markerPath)
		return err
	}
	state.Phase = phaseApplying
	if err := files.WriteJSONAtomic(markerPath, state, 0o600); err != nil {
		_ = restoreDirectory(current, backup)
		return err
	}
	if err := apply(filepath.Join(current, "generated")); err != nil {
		return errors.Join(err, restoreDirectory(current, backup), os.Remove(markerPath))
	}
	state.Phase = phaseCommitted
	if err := files.WriteJSONAtomic(markerPath, state, 0o600); err != nil {
		// Apply completed. Downgrading the marker would falsely trigger rollback on resume.
		return err
	}
	if backup != "" {
		_ = os.RemoveAll(backup)
	}
	return os.Remove(markerPath)
}

// Recover finishes or rolls back an interrupted publication safely.
//
//nolint:cyclop // Recovery dispatches on one closed phase enumeration for the durable transaction.
func (store Store) Recover() error {
	markerPath := filepath.Join(store.Root, ".transaction.json")
	data, err := os.ReadFile(markerPath) // #nosec G304 -- fixed path below validated root.
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var state marker
	if err := json.Unmarshal(data, &state); err != nil || state.APIVersion != APIVersion || !validName(state.Name) {
		return errors.New("installation transaction marker is invalid")
	}
	if state.Backup != "" && (!filepath.IsAbs(state.Backup) || filepath.Clean(state.Backup) != state.Backup) {
		return errors.New("installation transaction backup path is invalid")
	}
	current, err := store.Directory(state.Name)
	if err != nil {
		return err
	}
	switch state.Phase {
	case phasePublishing, phaseApplying:
		if err := restoreDirectory(current, state.Backup); err != nil {
			return err
		}
	case phaseCommitted:
		// Apply completed before the marker could be cleared. Finish by
		// discarding the backup while keeping the new installation source.
		if state.Backup != "" {
			if err := os.RemoveAll(state.Backup); err != nil {
				return err
			}
		}
	default:
		return errors.New("installation transaction marker phase is invalid")
	}
	return os.Remove(markerPath)
}

// Discard removes one installation source entirely without touching root state.
// It is used by removal and cleanup after a successful host uninstall.
func (store Store) Discard(name string) error {
	directory, err := store.Directory(name)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(directory); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func restoreDirectory(current, backup string) error {
	if err := os.RemoveAll(current); err != nil {
		return err
	}
	if backup == "" {
		return nil
	}
	return os.Rename(backup, current)
}

func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil || relative == ".." || filepath.IsAbs(relative) || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("generated installation tree is unsafe")
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("generated installation tree contains a non-regular file")
		}
		input, err := os.Open(path) // #nosec G304 -- compiler-owned tree path.
		if err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, info.Mode().Perm()) // #nosec G304 -- target below private staging.
		if err != nil {
			_ = input.Close()
			return err
		}
		_, copyErr := io.Copy(output, input)
		return errors.Join(copyErr, input.Close(), output.Sync(), output.Close())
	})
}
