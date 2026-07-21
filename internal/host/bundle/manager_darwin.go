//go:build darwin

package bundle

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

type launchdManager struct{ runner commandRunner }

func newNativeManager(runner commandRunner) ServiceManager { return &launchdManager{runner: runner} }

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed service-manager commands.
}

func (m *launchdManager) Stop(ctx context.Context, service string) error {
	return m.serviceAction(ctx, "kill", "SIGTERM", service)
}

func (m *launchdManager) Start(ctx context.Context, service string) error {
	return m.serviceAction(ctx, "kickstart", "-k", service)
}

func (m *launchdManager) serviceAction(ctx context.Context, action, option, service string) error {
	_, err := m.runner.Run(ctx, "launchctl", action, option, "system/"+service)
	return err
}

func (m *launchdManager) Reload(context.Context) error { return nil }

func (m *launchdManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	output, err := m.runner.Run(ctx, "launchctl", "print", "system/"+service)
	if err != nil {
		return ServiceStatus{}, nil
	}
	pid := launchdPID(string(output))
	if pid <= 0 {
		return ServiceStatus{}, errors.New("launchd service has no process")
	}
	executable, err := m.runner.Run(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	if err != nil {
		return ServiceStatus{}, err
	}
	return ServiceStatus{Active: true, PID: pid, Executable: strings.TrimSpace(string(executable))}, nil
}

func launchdPID(output string) int {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "pid" {
			pid, _ := strconv.Atoi(strings.TrimSpace(value))
			return pid
		}
	}
	return 0
}
