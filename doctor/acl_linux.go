//go:build linux

package doctor

import (
	"errors"
	"os"
	"syscall"
)

func pathACLState(path string) aclState {
	return mergeACLStates(
		xattrACLState(path, "system.posix_acl_access"),
		xattrACLState(path, "system.posix_acl_default"),
	)
}

func xattrACLState(path string, name string) aclState {
	_, err := syscall.Getxattr(path, name, nil)
	if err == nil || errors.Is(err, syscall.ERANGE) {
		return aclPresent
	}
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, os.ErrNotExist) {
		return aclAbsent
	}
	return aclUnknown
}

func mergeACLStates(left aclState, right aclState) aclState {
	if left == aclPresent || right == aclPresent {
		return aclPresent
	}
	if left == aclUnknown || right == aclUnknown {
		return aclUnknown
	}
	return aclAbsent
}
