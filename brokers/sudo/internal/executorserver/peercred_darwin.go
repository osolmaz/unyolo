//go:build darwin

package executorserver

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func DefaultPeerUID(connection *net.UnixConn) (uint32, error) {
	if connection == nil {
		return 0, errors.New("Unix connection is required")
	}
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			controlErr = err
			return
		}
		uid = credential.Uid
	}); err != nil {
		return 0, err
	}
	return uid, controlErr
}
