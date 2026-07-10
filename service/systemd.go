// Package service renders provider-neutral broker service definitions.
package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/internal/validatex"
)

// SystemdUnit describes one broker-family systemd service.
type SystemdUnit struct {
	Description     string
	User            string
	Group           string
	EnvironmentFile string
	ExecStart       string
	StateDir        string
	ConfigDir       string
	RestartSec      int
	ExtraDirectives []string
}

// RenderSystemd renders a hardened systemd unit using the shared broker-family
// baseline. Broker-specific directives may be appended to the Service section.
func RenderSystemd(unit SystemdUnit) (string, error) {
	if err := unit.validate(); err != nil {
		return "", err
	}
	restartSec := unit.RestartSec
	if restartSec <= 0 {
		restartSec = 5
	}
	var body strings.Builder
	_, _ = fmt.Fprintf(&body, `[Unit]
Description=%s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%s
Group=%s
EnvironmentFile=%s
ExecStart=%s
Restart=on-failure
RestartSec=%d
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=%s
ReadOnlyPaths=%s
`, unit.Description, unit.User, unit.Group, unit.EnvironmentFile, unit.ExecStart, restartSec, unit.StateDir, unit.ConfigDir)
	for _, directive := range unit.ExtraDirectives {
		body.WriteString(directive)
		body.WriteByte('\n')
	}
	body.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return body.String(), nil
}

func (unit SystemdUnit) validate() error {
	values := map[string]string{
		"description":      unit.Description,
		"user":             unit.User,
		"group":            unit.Group,
		"environment file": unit.EnvironmentFile,
		"exec start":       unit.ExecStart,
		"state directory":  unit.StateDir,
		"config directory": unit.ConfigDir,
	}
	if err := validateRequiredLines(values); err != nil {
		return err
	}
	if err := validatex.AbsolutePaths(map[string]string{
		"environment file": unit.EnvironmentFile,
		"state directory":  unit.StateDir,
		"config directory": unit.ConfigDir,
	}, false); err != nil {
		return err
	}
	if !strings.HasPrefix(unit.ExecStart, "/") {
		return errors.New("exec start must begin with an absolute binary path")
	}
	return validateExtraDirectives(unit.ExtraDirectives)
}

func validateExtraDirectives(directives []string) error {
	for _, directive := range directives {
		if strings.TrimSpace(directive) == "" || strings.ContainsAny(directive, "\r\n") || !strings.Contains(directive, "=") {
			return errors.New("extra systemd directives must be nonempty key=value lines")
		}
	}
	return nil
}

func validateRequiredLines(values map[string]string) error {
	for name, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s must be one line", name)
		}
	}
	return nil
}
