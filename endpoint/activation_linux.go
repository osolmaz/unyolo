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
	count, err := systemdActivationCount()
	if err != nil {
		return nil, err
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count || count != len(expected) {
		return nil, errors.New("systemd activation listener names are incomplete")
	}
	wanted, err := expectedActivationNames(expected)
	if err != nil {
		return nil, err
	}
	return acquireSystemdListeners(names, wanted)
}

func systemdActivationCount() (int, error) {
	pid, pidErr := strconv.Atoi(os.Getenv("LISTEN_PID"))
	count, countErr := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if pidErr != nil || countErr != nil || pid != os.Getpid() || count < 1 {
		return 0, errors.New("systemd activation environment is invalid")
	}
	return count, nil
}

func expectedActivationNames(expected []string) (map[string]struct{}, error) {
	wanted := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		if _, exists := wanted[name]; exists {
			return nil, fmt.Errorf("systemd activation listener %q is duplicated", name)
		}
		wanted[name] = struct{}{}
	}
	return wanted, nil
}

func acquireSystemdListeners(names []string, wanted map[string]struct{}) (map[string]interfaceListener, error) {
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
