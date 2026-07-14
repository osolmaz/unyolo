//go:build linux

package endpoint

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func activationListener(name string) (listener interfaceListener, err error) {
	rawPID, rawCount := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS")
	pid, pidErr := strconv.Atoi(rawPID)
	count, countErr := strconv.Atoi(rawCount)
	if pidErr != nil || countErr != nil || pid != os.Getpid() || count < 1 {
		return nil, errors.New("systemd activation environment is invalid")
	}
	names := strings.Split(os.Getenv("LISTEN_FDNAMES"), ":")
	if len(names) != count {
		return nil, errors.New("systemd activation listener names are incomplete")
	}
	found := -1
	for index, candidate := range names {
		if candidate == name {
			if found >= 0 {
				return nil, fmt.Errorf("systemd activation listener %q is duplicated", name)
			}
			found = index
		}
	}
	if found < 0 {
		return nil, fmt.Errorf("systemd activation listener %q is unavailable", name)
	}
	return listenerFromFD(3 + found)
}
