// Package hostcheck validates privileged filesystem facts.
package hostcheck

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
)

func ValidateExecution(value plan.Plan, brokerUID uint32) error {
	if err := validateTrustedChain(value.Executable, true, brokerUID, value.TargetUID); err != nil {
		return fmt.Errorf("executable path is unsafe: %w", err)
	}
	if err := validateTrustedChain(value.WorkingDirectory, false, brokerUID, value.TargetUID); err != nil {
		return fmt.Errorf("working directory is unsafe: %w", err)
	}
	return nil
}

func ValidateRootFile(path string) error {
	if err := validateTrustedChain(path, true, ^uint32(0), ^uint32(0)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("path must be a regular file")
	}
	return nil
}

func ValidateRootDirectory(path string) error {
	return validateTrustedChain(path, false, ^uint32(0), ^uint32(0))
}

func ValidateStaleSocket(path string, brokerUID uint32) error {
	if err := ValidateRootDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 {
		return errors.New("existing helper socket path is not a Unix socket")
	}
	uid, err := fileOwner(info)
	if err != nil {
		return err
	}
	if uid != 0 && uid != brokerUID {
		return errors.New("existing helper socket has an unexpected owner")
	}
	return nil
}

func validateTrustedChain(path string, finalFile bool, brokerUID uint32, targetUID uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and normalized")
	}
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	if path == current {
		components = nil
	}
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("lstat %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", current)
		}
		uid, err := fileOwner(info)
		if err != nil {
			return err
		}
		if uid != 0 || (uid == brokerUID && brokerUID != 0) || (uid == targetUID && targetUID != 0) {
			return fmt.Errorf("%s is not root-owned", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is group- or world-writable", current)
		}
		last := index == len(components)-1
		if !last || !finalFile {
			if !info.IsDir() {
				return fmt.Errorf("%s is not a directory", current)
			}
		} else if !info.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", current)
		}
	}
	return nil
}
