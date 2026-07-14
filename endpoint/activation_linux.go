//go:build linux

package endpoint

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func activationListeners(expected []string) (map[string]interfaceListener, error) {
	rawPID, rawCount := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	pid, pidErr := strconv.Atoi(rawPID)
	count, countErr := strconv.Atoi(rawCount)
	if pidErr != nil || countErr != nil || pid != os.Getpid() || count < 1 {
		return nil, errors.New("systemd activation environment is invalid")
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count || count != len(expected) {
		return nil, errors.New("systemd activation listener names are incomplete")
	}
	wanted := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		if _, exists := wanted[name]; exists {
			return nil, fmt.Errorf("systemd activation listener %q is duplicated", name)
		}
		wanted[name] = struct{}{}
	}
	listeners := make(map[string]interfaceListener, len(names))
	for index, name := range names {
		if _, exists := wanted[name]; !exists {
			return nil, closeActivatedListeners(listeners, fmt.Errorf("unexpected systemd activation listener %q", name))
		}
		if _, exists := listeners[name]; exists {
			return nil, closeActivatedListeners(listeners, fmt.Errorf("systemd activation listener %q is duplicated", name))
		}
		listener, err := listenerFromFD(3 + index)
		if err != nil {
			return nil, closeActivatedListeners(listeners, err)
		}
		listeners[name] = listener
	}
	return listeners, nil
}

func closeActivatedListeners(listeners map[string]interfaceListener, cause error) error {
	values := []error{cause}
	for _, listener := range listeners {
		values = append(values, listener.Close())
	}
	return errors.Join(values...)
}
