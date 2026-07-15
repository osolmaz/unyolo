//go:build darwin && !cgo

package endpoint

import (
	"errors"
	"net"
)

func activationListeners([]string) (map[string]net.Listener, error) {
	return nil, errors.New("launchd listener activation requires a native CGO build")
}
