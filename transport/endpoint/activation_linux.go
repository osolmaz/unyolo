//go:build linux

package endpoint

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/internal/setx"
)

func activationListeners(expected []string) (map[string]net.Listener, error) {
	return activationListenersWith(expected, listenerFromFD)
}

func activationListenersWith(expected []string, open func(int) (net.Listener, error)) (map[string]net.Listener, error) {
	count, err := systemdActivationCount()
	if err != nil {
		return nil, err
	}
	names, err := activationNamesFromEnv(count, len(expected))
	if err != nil {
		return nil, err
	}
	wanted, err := expectedActivationNames(expected)
	if err != nil {
		return nil, err
	}
	return acquireSystemdListeners(names, wanted, open)
}

func activationNamesFromEnv(count, expected int) ([]string, error) {
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count || count != expected {
		return nil, errors.New("systemd activation listener names are incomplete")
	}
	return names, nil
}

func systemdActivationCount() (int, error) {
	pid, count, err := parseSystemdActivationEnv()
	if err != nil || pid != os.Getpid() || count < 1 {
		return 0, errors.New("systemd activation environment is invalid")
	}
	return count, nil
}

func parseSystemdActivationEnv() (int, int, error) {
	pid, pidErr := strconv.Atoi(os.Getenv("LISTEN_PID"))
	count, countErr := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	return pid, count, errors.Join(pidErr, countErr)
}

func expectedActivationNames(expected []string) (map[string]struct{}, error) {
	wanted := make(map[string]struct{}, len(expected))
	for _, name := range expected {
		if !setx.Add(wanted, name) {
			return nil, fmt.Errorf("systemd activation listener %q is duplicated", name)
		}
	}
	return wanted, nil
}

func acquireSystemdListeners(names []string, wanted map[string]struct{}, open func(int) (net.Listener, error)) (map[string]net.Listener, error) {
	listeners := make(map[string]net.Listener, len(names))
	for index, name := range names {
		if err := validateActivatedName(name, wanted, listeners); err != nil {
			return nil, closeActivatedListeners(listeners, err)
		}
		listener, err := open(3 + index)
		if err != nil {
			return nil, closeActivatedListeners(listeners, err)
		}
		listeners[name] = listener
	}
	return listeners, nil
}

func validateActivatedName(name string, wanted map[string]struct{}, listeners map[string]net.Listener) error {
	if _, exists := wanted[name]; !exists {
		return fmt.Errorf("unexpected systemd activation listener %q", name)
	}
	if _, exists := listeners[name]; exists {
		return fmt.Errorf("systemd activation listener %q is duplicated", name)
	}
	return nil
}
