//go:build linux

package privexec

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

type childExecHandles struct {
	workingDirectory int
	executable       int
}

func executePlan(value plan.Plan) error {
	handles, err := prepareChildExec(value)
	if err != nil {
		return err
	}
	defer handles.Close()
	return handles.exec(value)
}

func prepareChildExec(value plan.Plan) (childExecHandles, error) {
	if err := applyLimits(value); err != nil {
		return childExecHandles{}, err
	}
	return openChildExecHandles(value)
}

func (h childExecHandles) exec(value plan.Plan) error {
	if err := enterChildExecutionContext(h.workingDirectory, value); err != nil {
		return err
	}
	argv := append([]string{value.Executable}, value.Arguments...)
	return execveat(h.executable, argv, append([]string(nil), value.Environment...))
}

func openChildExecHandles(value plan.Plan) (childExecHandles, error) {
	workingDirectory, err := openTrustedDirectory(value.WorkingDirectory)
	if err != nil {
		return childExecHandles{}, err
	}
	executable, err := openTrustedExecutable(value.Executable)
	if err != nil {
		_ = unix.Close(workingDirectory)
		return childExecHandles{}, err
	}
	return childExecHandles{workingDirectory: workingDirectory, executable: executable}, nil
}

func (h childExecHandles) Close() {
	_ = unix.Close(h.workingDirectory)
	_ = unix.Close(h.executable)
}

func openTrustedDirectory(path string) (int, error) {
	fd, err := openTrustedPath(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return -1, errors.New("open trusted working directory")
	}
	return fd, nil
}

func openTrustedExecutable(path string) (int, error) {
	fd, err := openTrustedPath(path, unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return -1, errors.New("open trusted executable")
	}
	if err := validateExecutableDescriptor(fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func enterChildExecutionContext(workingDirectory int, value plan.Plan) error {
	if err := unix.Fchdir(workingDirectory); err != nil {
		return errors.New("enter working directory")
	}
	return dropIdentityThenLimit(value)
}

func dropIdentityThenLimit(value plan.Plan) error {
	return firstError(func() error { return dropIdentity(value) }, applyPostIdentityLimits)
}

func openTrustedPath(path string, flags int) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags: uint64(flags), Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS, // #nosec G115 -- flags is a fixed nonnegative open-mode bitset.
	})
}

func inspectExecutableDescriptor(fd int) (executableDescriptorMetadata, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return executableDescriptorMetadata{}, err
	}
	return executableDescriptorMetadata{ownerUID: stat.Uid, mode: stat.Mode, regular: stat.Mode&unix.S_IFMT == unix.S_IFREG}, nil
}

func dropIdentity(value plan.Plan) error {
	return firstError(
		setSupplementaryGroups(value.SupplementaryGIDs),
		func() error { return setTargetID(value.TargetGID, "gid", syscall.Setgid) },
		func() error { return setTargetID(value.TargetUID, "uid", syscall.Setuid) },
	)
}

func firstError(checks ...func() error) error {
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func setSupplementaryGroups(values []uint32) func() error {
	return func() error {
		if err := syscall.Setgroups(supplementaryGroupInts(values)); err != nil {
			return errors.New("drop supplementary groups")
		}
		return nil
	}
}

func setTargetID(id uint32, kind string, set func(int) error) error {
	if err := set(int(id)); err != nil {
		return errors.New("drop target " + kind)
	}
	return nil
}

func supplementaryGroupInts(values []uint32) []int {
	groups := make([]int, len(values))
	for index, group := range values {
		groups[index] = int(group)
	}
	return groups
}

func execveat(fd int, argv []string, environment []string) error {
	empty, argvPointers, environmentPointers, err := execveInputs(argv, environment)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)), // #nosec G103 -- direct execveat is required for descriptor-bound execution.
		uintptr(unsafe.Pointer(&argvPointers[0])), environmentPointer(environmentPointers), uintptr(unix.AT_EMPTY_PATH), 0) // #nosec G103 -- argv pointers are NUL-terminated and retained for the syscall.
	runtime.KeepAlive(argvPointers)
	runtime.KeepAlive(environmentPointers)
	return errnoError(errno)
}

func errnoError(errno syscall.Errno) error {
	if errno != 0 {
		return errno
	}
	return nil
}

func execveInputs(argv []string, environment []string) (*byte, []*byte, []*byte, error) {
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return nil, nil, nil, err
	}
	argvPointers, environmentPointers, err := execvePointers(argv, environment)
	if err != nil {
		return nil, nil, nil, err
	}
	return empty, argvPointers, environmentPointers, nil
}

func execvePointers(argv []string, environment []string) ([]*byte, []*byte, error) {
	argvPointers, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return nil, nil, err
	}
	environmentPointers, err := syscall.SlicePtrFromStrings(environment)
	if err != nil {
		return nil, nil, err
	}
	return argvPointers, environmentPointers, nil
}

func environmentPointer(environmentPointers []*byte) uintptr {
	if len(environmentPointers) == 0 {
		return 0
	}
	return uintptr(unsafe.Pointer(&environmentPointers[0])) // #nosec G103 -- execveat requires stable C pointer arrays for this syscall.
}
