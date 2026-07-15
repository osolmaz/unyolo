package endpoint

import (
	"errors"
	"net"
)

type interfaceListener = net.Listener

func closeActivatedListeners(listeners map[string]interfaceListener, cause error) error {
	values := []error{cause}
	for _, listener := range listeners {
		values = append(values, listener.Close())
	}
	return errors.Join(values...)
}
