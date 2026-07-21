package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/internal/host/layout"
)

func validateManagedExecutableAccess(unit SystemdUnit) error {
	return validateManagedExecutableAccessAt(unit, layout.LinuxRoot())
}

//nolint:cyclop // Validation keeps every ownership, link-target, and release-boundary check explicit.
func validateManagedExecutableAccessAt(unit SystemdUnit, root string) error {
	destination := unit.ManagedExecutableDestination
	if err := validateManagedExecutableReferenceAt(unit, root); err != nil {
		return err
	}
	executable := strings.SplitN(unit.ExecStart, " ", 2)[0]
	current := filepath.Join(root, "current")
	if err := validateTrustedServicePath("managed release root", root, ""); err != nil {
		return err
	}
	info, err := os.Lstat(current)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return errors.New("managed current release pointer is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("managed current release pointer must be root-owned")
	}
	target, err := os.Readlink(current)
	if err != nil || !layout.ValidCurrentTarget(target) {
		return errors.New("managed current release pointer is outside the immutable release root")
	}
	resolved, err := filepath.EvalSymlinks(executable)
	if err != nil || layout.ReleaseDestination(resolved, root) != destination {
		return errors.New("managed executable does not resolve inside the active immutable release")
	}
	if err := validateTrustedServicePath("executable", resolved, ""); err != nil {
		return err
	}
	return validateTrustedExecutableAccessPath(resolved, unit.User, unit.Group)
}

func validateManagedExecutableReference(unit SystemdUnit) error {
	return validateManagedExecutableReferenceAt(unit, layout.LinuxRoot())
}

func validateManagedExecutableReferenceAt(unit SystemdUnit, root string) error {
	destination := unit.ManagedExecutableDestination
	if destination == "" {
		return nil
	}
	if !layout.SafeDestination(destination) {
		return errors.New("managed executable destination is invalid")
	}
	executable := strings.SplitN(unit.ExecStart, " ", 2)[0]
	if executable != filepath.Join(root, "current", destination) {
		return errors.New("managed executable does not use its exact current release path")
	}
	return nil
}

func validateTrustedExecutableAccess(unit SystemdUnit) error {
	path := strings.SplitN(unit.ExecStart, " ", 2)[0]
	return validateTrustedExecutableAccessPath(path, unit.User, unit.Group)
}

func validateTrustedExecutableAccessPath(path, userName, groupName string) error {
	uid, groupIDs, err := systemIdentityAccessIDs(userName, groupName)
	if err != nil {
		return err
	}
	return validateExecutableAccessForIdentity(path, userName, uid, groupIDs)
}

func validateExecutableAccessForIdentity(path string, userName string, uid uint64, groupIDs map[uint64]struct{}) error {
	mode, ownerUID, ownerGID, err := trustedExecutableMetadata(path)
	if err != nil {
		return err
	}
	if err := validateExecutableAncestorAccess(path, uid, groupIDs); err != nil {
		return err
	}
	if !identityCanExecuteWithGroups(mode, ownerUID, ownerGID, uid, groupIDs) {
		return fmt.Errorf("executable is not executable by service user %s", userName)
	}
	return nil
}

func validateExecutableAncestorAccess(path string, uid uint64, groupIDs map[uint64]struct{}) error {
	components := strings.Split(strings.TrimPrefix(filepath.Dir(path), string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, component := range components {
		if component != "" {
			current = filepath.Join(current, component)
		}
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect executable ancestor: %w", err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("executable ancestor ownership is unavailable: %s", current)
		}
		if !identityCanSearch(info.Mode().Perm(), uint64(stat.Uid), uint64(stat.Gid), uid, groupIDs) {
			return fmt.Errorf("executable ancestor is not searchable by service user: %s", current)
		}
	}
	return nil
}

func trustedExecutableMetadata(path string) (os.FileMode, uint64, uint64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("inspect executable: %w", err)
	}
	if !info.Mode().IsRegular() {
		return 0, 0, 0, errors.New("executable must be a regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, 0, errors.New("executable ownership is unavailable")
	}
	return info.Mode().Perm(), uint64(stat.Uid), uint64(stat.Gid), nil
}

func systemIdentityIDs(userName string, groupName string) (uint64, uint64, error) {
	account, err := lookupSystemUser(userName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup service user %q: %w", userName, err)
	}
	group, err := lookupSystemGroup(groupName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup service group %q: %w", groupName, err)
	}
	uid, err := parseSystemID("uid", userName, account.Uid)
	if err != nil {
		return 0, 0, err
	}
	gid, err := parseSystemID("gid", groupName, group.Gid)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func systemIdentityAccessIDs(userName string, groupName string) (uint64, map[uint64]struct{}, error) {
	uid, primaryGID, err := systemIdentityIDs(userName, groupName)
	if err != nil {
		return 0, nil, err
	}
	account, err := lookupSystemUser(userName)
	if err != nil {
		return 0, nil, fmt.Errorf("lookup service user %q groups: %w", userName, err)
	}
	values, err := lookupSystemGroupIDs(account)
	if err != nil {
		return 0, nil, fmt.Errorf("lookup supplementary groups for %q: %w", userName, err)
	}
	groupIDs := map[uint64]struct{}{primaryGID: {}}
	for _, value := range values {
		gid, err := parseSystemID("supplementary gid", userName, value)
		if err != nil {
			return 0, nil, err
		}
		groupIDs[gid] = struct{}{}
	}
	return uid, groupIDs, nil
}

func parseSystemID(kind string, name string, value string) (uint64, error) {
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse %s for %q: %w", kind, name, err)
	}
	return id, nil
}
