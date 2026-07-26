package profile

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const MaxArtifactBytes = 256 * 1024 * 1024

// VerifyArtifact verifies one signed runtime artifact inside the pack and
// returns its absolute source path. Callers must not execute this user-owned
// path with elevated privilege; copy it into a verified root-owned staging
// directory first.
//
//nolint:cyclop // Artifact verification keeps every path and digest rejection in one trust-boundary function.
func (snapshot Snapshot) VerifyArtifact(source, expected string) (string, error) {
	if err := validateRelative(source); err != nil {
		return "", err
	}
	root, err := os.OpenRoot(snapshot.Root)
	if err != nil {
		return "", err
	}
	defer func() { _ = root.Close() }()
	if err := inspectPath(root, source); err != nil {
		return "", err
	}
	file, err := root.Open(source)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, MaxArtifactBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	if written > MaxArtifactBytes {
		return "", errors.New("runtime artifact exceeds size limit")
	}
	actual := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	if actual != expected {
		return "", errors.New("runtime artifact digest mismatch")
	}
	path := filepath.Join(snapshot.Root, filepath.FromSlash(source))
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("setup adapter artifact is not executable")
	}
	return path, nil
}
