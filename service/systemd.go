// Package service renders provider-neutral broker service definitions.
package service

import (
	"errors"
	"fmt"
	"path/filepath"
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
	HomeAccess      HomeAccess
	ExtraDirectives []string
}

// HomeAccess controls service visibility into user home directories.
type HomeAccess string

const (
	// HomeAccessDeny hides home directories and is the default.
	HomeAccessDeny HomeAccess = "deny"
	// HomeAccessReadOnly permits reads but not writes except explicit writable paths.
	HomeAccessReadOnly HomeAccess = "read-only"
	// HomeAccessAllow permits broker-specific user-home operations.
	HomeAccessAllow HomeAccess = "allow"
)

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
	protectHome := protectHomeValue(unit.HomeAccess)
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
ProtectHome=%s
ReadWritePaths=%s
ReadOnlyPaths=%s
`, unit.Description, unit.User, unit.Group, unit.EnvironmentFile, unit.ExecStart, restartSec, protectHome, unit.StateDir, unit.ConfigDir)
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
	if err := validatex.AccountNames(map[string]string{"user": unit.User, "group": unit.Group}); err != nil {
		return err
	}
	if err := validateHomeAccess(unit.HomeAccess); err != nil {
		return err
	}
	if err := validateSystemdUnitPaths(unit); err != nil {
		return err
	}
	return validateExtraDirectives(unit.ExtraDirectives)
}

func validateSystemdUnitPaths(unit SystemdUnit) error {
	if err := validatex.AbsolutePaths(map[string]string{
		"environment file": unit.EnvironmentFile,
		"state directory":  unit.StateDir,
		"config directory": unit.ConfigDir,
	}, false); err != nil {
		return err
	}
	if err := validateExecStart(unit.ExecStart); err != nil {
		return err
	}
	return validateProtectedServicePaths(unit)
}

func validateExecStart(value string) error {
	if !strings.HasPrefix(value, "/") {
		return errors.New("exec start must begin with an absolute binary path")
	}
	if strings.ContainsAny(value, "\t%\\\"'$;") {
		return errors.New("exec start contains unsupported systemd syntax")
	}
	return nil
}

func validateProtectedServicePaths(unit SystemdUnit) error {
	paths := map[string]string{
		"environment file": unit.EnvironmentFile,
		"state directory":  unit.StateDir,
		"config directory": unit.ConfigDir,
		"executable":       strings.SplitN(unit.ExecStart, " ", 2)[0],
	}
	for name, value := range paths {
		if err := validateSystemdPath(name, value); err != nil {
			return err
		}
		if normalizedHomeAccess(unit.HomeAccess) == HomeAccessDeny && protectedHomePath(value) {
			return fmt.Errorf("%s must not be under a path hidden by ProtectHome", name)
		}
	}
	if filepath.Clean(unit.StateDir) == string(filepath.Separator) {
		return errors.New("state directory must not make the filesystem root writable")
	}
	return nil
}

func validateHomeAccess(value HomeAccess) error {
	switch normalizedHomeAccess(value) {
	case HomeAccessDeny, HomeAccessReadOnly, HomeAccessAllow:
		return nil
	default:
		return fmt.Errorf("home access %q is invalid", value)
	}
}

func normalizedHomeAccess(value HomeAccess) HomeAccess {
	if value == "" {
		return HomeAccessDeny
	}
	return value
}

func protectHomeValue(value HomeAccess) string {
	switch normalizedHomeAccess(value) {
	case HomeAccessReadOnly:
		return "read-only"
	case HomeAccessAllow:
		return "false"
	case HomeAccessDeny:
		return "true"
	default:
		return "true"
	}
}

func protectedHomePath(value string) bool {
	cleaned := filepath.Clean(value)
	for _, root := range []string{"/home", "/root", "/run/user"} {
		if cleaned == root || strings.HasPrefix(cleaned, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
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
