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

// Enable bootstraps the LaunchDaemon with launchctl, loading its root-owned
// plist and starting it under launchd's supervision.
func (m *launchdManager) Enable(ctx context.Context, service string) error {
	if m.registered(ctx, service) {
		return nil
	}
	_, err := m.runner.Run(ctx, "launchctl", "bootstrap", "system", launchdPlistPath(service))
	return err
}

// Disable unloads the LaunchDaemon with launchctl bootout so a subsequent
// Enable can restore the prior state.
func (m *launchdManager) Disable(ctx context.Context, service string) error {
	if !m.registered(ctx, service) {
		return nil
	}
	_, err := m.runner.Run(ctx, "launchctl", "bootout", launchdSystemTarget(service))
	return err
}

func (m *launchdManager) registered(ctx context.Context, service string) bool {
	_, err := m.runner.Run(ctx, "launchctl", "print", launchdSystemTarget(service))
	return err == nil
}

func (m *launchdManager) serviceAction(ctx context.Context, action, option, service string) error {
	_, err := m.runner.Run(ctx, "launchctl", action, option, launchdSystemTarget(service))
	return err
}

func (m *launchdManager) Reload(context.Context) error { return nil }

func (m *launchdManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	output, err := m.runner.Run(ctx, "launchctl", "print", launchdSystemTarget(service))
	if err != nil {
		return ServiceStatus{}, nil
	}
	pid := launchdParsePID(string(output))
	if pid <= 0 {
		return ServiceStatus{}, errors.New("launchd service has no process")
	}
	executable, err := m.runner.Run(ctx, "ps", "-p", strconv.Itoa(pid), "-o", "comm=")
	if err != nil {
		return ServiceStatus{}, err
	}
	return ServiceStatus{Active: true, PID: pid, Executable: strings.TrimSpace(string(executable))}, nil
}
