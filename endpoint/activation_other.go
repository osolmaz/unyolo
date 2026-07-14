//go:build !linux && !darwin

package endpoint

import (
	"errors"
	"net"
)

func activationListener(string) (net.Listener, error) {
	return nil, errors.New("named listener activation is unsupported on this platform")
}
