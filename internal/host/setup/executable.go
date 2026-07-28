package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/osolmaz/unyolo/internal/host/layout"
)

// VerifyRootOwnedExecutable rejects a running binary or ancestor that a
// non-root user can replace. Privileged host deployment commands call this
// before inspecting or mutating protected state.
func VerifyRootOwnedExecutable() error {
	path, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve executable identity: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("privileged executable must be a regular executable file")
	}
	return validateTrustedExecutable(resolved)
}

// ManagedRoot is the root-controlled release directory used by service setup.
func ManagedRoot() string {
	return layout.Root()
}

// ManagedExecutablePath returns the stable service path for one bundle artifact.
func ManagedExecutablePath(destination string) string {
	return layout.ExecutablePath(destination)
}

// ManagedDestination returns destination only when path is its exact stable
// service path. It lets renderers mark production-managed units explicitly.
func ManagedDestination(path, destination string) string {
	if path == ManagedExecutablePath(destination) {
		return destination
	}
	return ""
}

// ResolveServiceExecutable preserves the stable managed pointer while rejecting
// unsafe or stale targets. The managed target may be absent during first setup;
// activation publishes it before starting the service.
func ResolveServiceExecutable(path, destination string, allowNonRoot bool) (string, bool, error) {
	return resolveServiceExecutable(path, ManagedRoot(), destination, os.Geteuid() == 0 && !allowNonRoot)
}

func resolveServiceExecutable(path, root, destination string, trusted bool) (string, bool, error) {
	if !safeManagedDestination(destination) {
		return "", false, errors.New("managed executable destination is invalid")
	}
	path, err := resolveInputExecutable(path)
	if err != nil {
		return "", false, err
	}
	managed := filepath.Join(root, "current", destination)
	if path == managed {
		return resolveManagedExecutable(managed, root, destination, trusted)
	}
	return resolveExistingExecutable(path, managed, root, destination, trusted)
}

func resolveInputExecutable(path string) (string, error) {
	if path == "" {
		var err error
		path, err = os.Executable()
		if err != nil {
			return "", fmt.Errorf("resolve executable path: %w", err)
		}
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("executable path must be absolute and normalized")
	}
	return path, nil
}

func resolveManagedExecutable(managed, root, destination string, trusted bool) (string, bool, error) {
	if err := validateManagedExecutable(root, destination, trusted); err != nil {
		return "", false, err
	}
	return managed, true, nil
}

func resolveExistingExecutable(path, managed, root, destination string, trusted bool) (string, bool, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", false, fmt.Errorf("resolve executable path: %w", err)
	}
	if layout.ReleaseDestination(resolved, root) == destination {
		if err := validateExistingExecutable(resolved, trusted); err != nil {
			return "", false, err
		}
		return managed, true, nil
	}
	if err := validateExistingExecutable(resolved, trusted); err != nil {
		return "", false, err
	}
	return resolved, false, nil
}

func validateManagedExecutable(root, destination string, trusted bool) error {
	current := filepath.Join(root, "current")
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		if trusted {
			return validateTrustedAncestor(root)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed release pointer: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("managed current release pointer is not a symlink")
	}
	target, err := os.Readlink(current)
	if err != nil || !layout.ValidCurrentTarget(target) {
		return errors.New("managed current release pointer is invalid")
	}
	resolved := filepath.Join(root, target, destination)
	return validateExistingExecutable(resolved, trusted)
}

func validateExistingExecutable(path string, trusted bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat executable path: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("executable path must be a regular executable file")
	}
	if trusted {
		return validateTrustedExecutable(path)
	}
	return nil
}

func validateTrustedAncestor(path string) error {
	current := filepath.Clean(path)
	for {
		if _, err := os.Lstat(current); err == nil {
			return validateTrustedExecutable(current)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect managed release root: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return errors.New("managed release root has no trusted ancestor")
		}
		current = parent
	}
}

func validateTrustedExecutable(path string) error {
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(path), current), current) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect executable path: %w", err)
		}
		if err := validateTrustedPathComponent(current, info); err != nil {
			return err
		}
	}
	return nil
}

func validateTrustedPathComponent(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("executable path ownership is unavailable for %s", path)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("executable path component must be root-owned: %s", path)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("executable path component must not be mutable by non-root users: %s", path)
	}
	return nil
}

func requiresManagedExecutable(opts SystemdOptions) bool {
	return os.Geteuid() == 0 && !opts.AllowNonRoot && !opts.DryRun
}

func safeManagedDestination(path string) bool {
	return layout.SafeDestination(path)
}
