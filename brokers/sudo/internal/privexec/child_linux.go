//go:build linux

package privexec

import (
	"errors"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

func executePlan(value plan.Plan) error {
	if err := applyLimits(value); err != nil {
		return err
	}
	workingDirectory, err := openTrustedPath(value.WorkingDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC)
	if err != nil {
		return errors.New("open trusted working directory")
	}
	defer func() { _ = unix.Close(workingDirectory) }()
	executable, err := openTrustedPath(value.Executable, unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		return errors.New("open trusted executable")
	}
	defer func() { _ = unix.Close(executable) }()
	if err := validateExecutableDescriptor(executable); err != nil {
		return err
	}
	if err := unix.Fchdir(workingDirectory); err != nil {
		return errors.New("enter working directory")
	}
	if err := dropIdentity(value); err != nil {
		return err
	}
	argv := append([]string{value.Executable}, value.Arguments...)
	return execveat(executable, argv, append([]string(nil), value.Environment...))
}

func openTrustedPath(path string, flags int) (int, error) {
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags: uint64(flags), Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS, // #nosec G115 -- flags is a fixed nonnegative open-mode bitset.
	})
}

func validateExecutableDescriptor(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return errors.New("inspect executable descriptor")
	}
	if stat.Uid != 0 || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 {
		return errors.New("executable descriptor is not trusted")
	}
	return nil
}

func dropIdentity(value plan.Plan) error {
	groups := make([]int, len(value.SupplementaryGIDs))
	for index, group := range value.SupplementaryGIDs {
		groups[index] = int(group)
	}
	if err := syscall.Setgroups(groups); err != nil {
		return errors.New("drop supplementary groups")
	}
	if err := syscall.Setgid(int(value.TargetGID)); err != nil {
		return errors.New("drop target gid")
	}
	if err := syscall.Setuid(int(value.TargetUID)); err != nil {
		return errors.New("drop target uid")
	}
	return nil
}

func execveat(fd int, argv []string, environment []string) error {
	empty, err := syscall.BytePtrFromString("")
	if err != nil {
		return err
	}
	argvPointers, err := syscall.SlicePtrFromStrings(argv)
	if err != nil {
		return err
	}
	environmentPointers, err := syscall.SlicePtrFromStrings(environment)
	if err != nil {
		return err
	}
	environmentPointer := uintptr(0)
	if len(environmentPointers) > 0 {
		environmentPointer = uintptr(unsafe.Pointer(&environmentPointers[0])) // #nosec G103 -- execveat requires stable C pointer arrays for this syscall.
	}
	_, _, errno := unix.Syscall6(unix.SYS_EXECVEAT, uintptr(fd), uintptr(unsafe.Pointer(empty)), // #nosec G103 -- direct execveat is required for descriptor-bound execution.
		uintptr(unsafe.Pointer(&argvPointers[0])), environmentPointer, uintptr(unix.AT_EMPTY_PATH), 0) // #nosec G103 -- argv pointers are NUL-terminated and retained for the syscall.
	runtime.KeepAlive(argvPointers)
	runtime.KeepAlive(environmentPointers)
	if errno != 0 {
		return errno
	}
	return nil
}
