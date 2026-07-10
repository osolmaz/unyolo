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

var allowedExtraSystemdDirectives = map[string]string{
	"LockPersonality":         "true",
	"MemoryDenyWriteExecute":  "true",
	"PrivateDevices":          "true",
	"ProtectClock":            "true",
	"ProtectControlGroups":    "true",
	"ProtectHostname":         "true",
	"ProtectKernelLogs":       "true",
	"ProtectKernelModules":    "true",
	"ProtectKernelTunables":   "true",
	"RemoveIPC":               "true",
	"RestrictNamespaces":      "true",
	"RestrictRealtime":        "true",
	"RestrictSUIDSGID":        "true",
	"SystemCallArchitectures": "native",
	"UMask":                   "0077",
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
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
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
	if strings.ContainsAny(unit.ExecStart, "\t%\\\"'") {
		return errors.New("exec start contains unsupported systemd syntax")
	}
	for name, value := range map[string]string{
		"environment file": unit.EnvironmentFile,
		"state directory":  unit.StateDir,
		"config directory": unit.ConfigDir,
	} {
		if err := validateSystemdPath(name, value); err != nil {
			return err
		}
	}
	return validateExtraDirectives(unit.ExtraDirectives)
}

func validateExtraDirectives(directives []string) error {
	for _, directive := range directives {
		if err := validateExtraDirective(directive); err != nil {
			return err
		}
	}
	return nil
}

func validateExtraDirective(directive string) error {
	if strings.TrimSpace(directive) == "" || strings.ContainsAny(directive, "\r\n") || !strings.Contains(directive, "=") {
		return errors.New("extra systemd directives must be nonempty key=value lines")
	}
	key, value, _ := strings.Cut(directive, "=")
	if key != strings.TrimSpace(key) || strings.ContainsAny(key, " \t.[]") {
		return fmt.Errorf("extra systemd directive key %q is invalid", key)
	}
	if allowedValue, exists := allowedExtraSystemdDirectives[key]; !exists || value != allowedValue {
		return fmt.Errorf("extra systemd directive %q is not an allowed additive hardening setting", directive)
	}
	return nil
}

func validateSystemdPath(name string, value string) error {
	for _, char := range value {
		if !isSystemdPathCharacter(char) {
			return fmt.Errorf("%s contains unsupported systemd path character %q", name, char)
		}
	}
	return nil
}

func isSystemdPathCharacter(char rune) bool {
	switch {
	case char >= 'a' && char <= 'z':
		return true
	case char >= 'A' && char <= 'Z':
		return true
	case char >= '0' && char <= '9':
		return true
	default:
		return strings.ContainsRune("/._+-", char)
	}
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
