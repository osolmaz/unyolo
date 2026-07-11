//go:build linux

package hostcheck

import "golang.org/x/sys/unix"

func KernelExecutionSafety() (bool, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, "/usr/bin/true", &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return false, err
	}
	_ = unix.Close(fd)
	return true, nil
}
