//go:build linux

package bundle

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type systemdManager struct{ runner commandRunner }

func newNativeManager(runner commandRunner) ServiceManager { return &systemdManager{runner: runner} }

func runCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- fixed service-manager commands.
}

func (m *systemdManager) Stop(ctx context.Context, service string) error {
	return m.serviceAction(ctx, "stop", service)
}

func (m *systemdManager) Start(ctx context.Context, service string) error {
	return m.serviceAction(ctx, "start", service)
}

func (m *systemdManager) serviceAction(ctx context.Context, action, service string) error {
	_, err := m.runner.Run(ctx, "systemctl", action, service)
	return err
}

func (m *systemdManager) Reload(ctx context.Context) error {
	_, err := m.runner.Run(ctx, "systemctl", "daemon-reload")
	return err
}

func (m *systemdManager) Status(ctx context.Context, service string) (ServiceStatus, error) {
	if _, err := m.runner.Run(ctx, "systemctl", "is-active", "--quiet", service); err != nil {
		return ServiceStatus{}, nil
	}
	output, err := m.runner.Run(ctx, "systemctl", "show", "--property=MainPID", "--value", service)
	if err != nil {
		return ServiceStatus{}, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(output)))
	if err != nil || pid <= 0 {
		return ServiceStatus{}, errors.New("systemd service has no main process")
	}
	executable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return ServiceStatus{}, err
	}
	return ServiceStatus{Active: true, PID: pid, Executable: executable}, nil
}
