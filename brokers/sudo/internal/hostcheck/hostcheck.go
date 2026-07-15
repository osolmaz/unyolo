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
	return validateStaleSocketInfo(info, brokerUID)
}

func validateStaleSocketInfo(info os.FileInfo, brokerUID uint32) error {
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
		last := index == len(components)-1
		if err := validateTrustedComponent(current, info, trustedComponentRules{
			finalFile: finalFile, last: last, brokerUID: brokerUID, targetUID: targetUID,
		}); err != nil {
			return err
		}
	}
	return nil
}

type trustedComponentRules struct {
	finalFile bool
	last      bool
	brokerUID uint32
	targetUID uint32
}

func validateTrustedComponent(path string, info os.FileInfo, rules trustedComponentRules) error {
	if err := validateTrustedComponentOwnership(path, info, rules.brokerUID, rules.targetUID); err != nil {
		return err
	}
	if err := validateTrustedComponentKind(path, info, rules.finalFile, rules.last); err != nil {
		return err
	}
	return nil
}

func validateTrustedComponentOwnership(path string, info os.FileInfo, brokerUID uint32, targetUID uint32) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if err := validateRootOwner(path, info, brokerUID, targetUID); err != nil {
		return err
	}
	return validateTrustedPermissions(path, info)
}

func validateRootOwner(path string, info os.FileInfo, brokerUID uint32, targetUID uint32) error {
	uid, err := fileOwner(info)
	if err != nil {
		return err
	}
	if !trustedRootOwner(uid) {
		return fmt.Errorf("%s is not root-owned", path)
	}
	return nil
}

func trustedRootOwner(uid uint32) bool { return uid == 0 }

func validateTrustedPermissions(path string, info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable", path)
	}
	if err := validatePathACL(path, info.IsDir()); err != nil {
		return fmt.Errorf("%s ACL is unsafe: %w", path, err)
	}
	return nil
}

func validateTrustedComponentKind(path string, info os.FileInfo, finalFile bool, last bool) error {
	if !last || !finalFile {
		if !info.IsDir() {
			return fmt.Errorf("%s is not a directory", path)
		}
		return nil
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}
