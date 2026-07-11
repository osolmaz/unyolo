//go:build !linux && !darwin

package executorserver

import (
	"errors"
	"net"
)

func DefaultPeerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("Unix peer credentials are unsupported on this platform")
}
