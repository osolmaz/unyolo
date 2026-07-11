//go:build linux

package hostcheck

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func validatePathACL(path string, directory bool) error {
	return validatePathACLWith(path, directory, unix.Lgetxattr)
}

func validatePathACLWith(path string, directory bool, get func(string, string, []byte) (int, error)) error {
	names := []string{"system.posix_acl_access"}
	if directory {
		names = append(names, "system.posix_acl_default")
	}
	for _, name := range names {
		size, err := get(path, name, nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", name, err)
		}
		if size > 0 {
			return errors.New("extended POSIX ACL is present")
		}
	}
	return nil
}
