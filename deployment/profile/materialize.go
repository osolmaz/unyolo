package profile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
)

// Materialize copies one verified deployment kit into an operator-owned pack.
// Only the locked profile graph and signed runtime artifacts are copied.
//
//nolint:cyclop // Validation, idempotent reuse, staged copy, and atomic publication share one materialization boundary.
func Materialize(snapshot Snapshot, destination string) (string, error) {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination || destination == snapshot.Root {
		return "", errors.New("deployment materialization destination is invalid")
	}
	if _, statErr := os.Lstat(destination); statErr == nil {
		existing, err := Load(destination)
		if err != nil {
			return "", fmt.Errorf("inspect deployment destination: %w", err)
		}
		if existing.Digest == snapshot.Digest {
			return destination, nil
		}
		return "", errors.New("deployment destination contains a different locked pack")
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect deployment destination: %w", statErr)
	}
	parent := filepath.Dir(destination)
	if err := ensureMaterializationParent(parent); err != nil {
		return "", err
	}
	staging, err := os.MkdirTemp(parent, ".brokerkit-deployment-*")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(staging) }()
	if err := os.Chmod(staging, 0o700); err != nil { // #nosec G302 -- staging is an owner-only directory, not a credential file.
		return "", err
	}
	paths, err := materializationPaths(snapshot)
	if err != nil {
		return "", err
	}
	for _, relative := range paths {
		if err := copyMaterializedFile(snapshot.Root, staging, relative); err != nil {
			return "", err
		}
	}
	if err := Lock(staging, true); err != nil {
		return "", fmt.Errorf("verify materialized deployment lock: %w", err)
	}
	if err := os.Rename(staging, destination); err != nil {
		return "", err
	}
	return destination, syncMaterializationDirectory(parent)
}

func syncMaterializationDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- validated operator-owned deployment parent.
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}

func materializationPaths(snapshot Snapshot) ([]string, error) {
	seen := map[string]bool{EntryFilename: true}
	result := []string{EntryFilename}
	for _, file := range snapshot.Files {
		if !seen[file.Path] {
			seen[file.Path] = true
			result = append(result, file.Path)
		}
	}
	for _, component := range snapshot.Manifest.Components {
		if _, err := snapshot.VerifyArtifact(component.Source, component.SHA256); err != nil {
			return nil, err
		}
		if !seen[component.Source] {
			seen[component.Source] = true
			result = append(result, component.Source)
		}
	}
	slices.Sort(result)
	return result, nil
}

func ensureMaterializationParent(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("deployment materialization parent must be an owner-only real directory")
	}
	return nil
}

//nolint:cyclop // Copying verifies source type, destination confinement, bounds, mode, close, and size together.
func copyMaterializedFile(sourceRoot, destinationRoot, relative string) error {
	if err := validateRelative(relative); err != nil {
		return err
	}
	source := filepath.Join(sourceRoot, filepath.FromSlash(relative))
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("deployment materialization source is not a regular file")
	}
	destination := filepath.Join(destinationRoot, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	input, err := os.Open(source) // #nosec G304 -- source is a verified pack-relative regular file.
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	mode := os.FileMode(0o600)
	if info.Mode().Perm()&0o111 != 0 {
		mode = 0o700
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- destination is in a private new staging directory.
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, io.LimitReader(input, MaxArtifactBytes+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if copied, statErr := os.Stat(destination); statErr != nil || copied.Size() > MaxArtifactBytes {
		return errors.New("materialized deployment file exceeds size limit")
	}
	return nil
}
