package deployment

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/osolmaz/brokerkit/deployment/profile"
	"github.com/osolmaz/brokerkit/internal/host/bundle"
)

//nolint:cyclop // Staging verifies source and destination metadata around one atomic copy.
func (engine *Engine) stageAdapter(snapshot profile.Snapshot, component bundle.Component, source string) (string, error) {
	directory := filepath.Join(engine.options.Paths.StateDir, "setup-adapters", snapshot.Digest[7:])
	if err := ensureStageDirectory(directory, engine.options.Paths.StateDir, engine.options.Development); err != nil {
		return "", err
	}
	destination := filepath.Join(directory, component.Name)
	if valid, err := stagedMatches(destination, component.SHA256, engine.options.Development); err != nil {
		return "", err
	} else if valid {
		return destination, nil
	}
	input, err := os.Open(source) // #nosec G304 -- source bytes are checked against the signed digest while copied.
	if err != nil {
		return "", err
	}
	defer func() { _ = input.Close() }()
	output, err := os.CreateTemp(directory, ".adapter-*")
	if err != nil {
		return "", err
	}
	temporary := output.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := output.Chmod(0o700); err != nil {
		_ = output.Close()
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(input, profile.MaxArtifactBytes+1))
	if copyErr != nil || written > profile.MaxArtifactBytes {
		_ = output.Close()
		return "", errors.New("copy setup adapter")
	}
	actual := fmt.Sprintf("sha256:%x", hash.Sum(nil))
	if actual != component.SHA256 {
		_ = output.Close()
		return "", errors.New("setup adapter changed while staging")
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return "", err
	}
	if err := output.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, destination); err != nil {
		return "", err
	}
	if valid, err := stagedMatches(destination, component.SHA256, engine.options.Development); err != nil || !valid {
		return "", errors.Join(err, errors.New("staged setup adapter failed verification"))
	}
	return destination, nil
}

//nolint:cyclop // Every parent ownership and permission constraint is checked before root execution.
func ensureStageDirectory(path, trustedRoot string, development bool) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return errors.New("setup adapter staging path is unsafe")
		}
		if !development {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("setup adapter staging path must be root-owned")
			}
		}
		if current == filepath.Clean(trustedRoot) {
			break
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("setup adapter staging escaped host state")
		}
		current = parent
	}
	return nil
}

//nolint:cyclop // Reuse requires matching type, ownership, mode, and digest.
func stagedMatches(path, expected string, development bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		return false, errors.New("staged setup adapter mode is unsafe")
	}
	if !development {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return false, errors.New("staged setup adapter must be root-owned")
		}
	}
	file, err := os.Open(path) // #nosec G304 -- fixed staged path.
	if err != nil {
		return false, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, io.LimitReader(file, profile.MaxArtifactBytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written > profile.MaxArtifactBytes {
		return false, errors.Join(copyErr, closeErr)
	}
	return fmt.Sprintf("sha256:%x", hash.Sum(nil)) == expected, nil
}
