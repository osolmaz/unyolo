package service

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/osolmaz/brokerkit/internal/validatex"
)

// LaunchdSocket describes one named launchd listener.
type LaunchdSocket struct {
	Name          string
	Path          string
	Owner         string
	Group         string
	Mode          os.FileMode
	DirectoryMode os.FileMode
}

// LaunchdUnit describes one system LaunchDaemon. ProgramArguments is rendered
// directly; launchd never invokes a shell or expands environment variables.
type LaunchdUnit struct {
	Label             string
	ProgramArguments  []string
	UserName          string
	GroupName         string
	Environment       map[string]string
	Sockets           []LaunchdSocket
	WorkingDirectory  string
	RootDirectory     string
	ProcessType       string
	ThrottleInterval  int
	KeepAlive         bool
	RunAtLoad         bool
	StandardOutPath   string
	StandardErrorPath string
}

// RenderLaunchd renders a complete system LaunchDaemon plist.
func RenderLaunchd(unit LaunchdUnit) (string, error) {
	if err := unit.validate(); err != nil {
		return "", err
	}
	var body bytes.Buffer
	body.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	body.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	body.WriteString("<plist version=\"1.0\">\n<dict>\n")
	writeLaunchdString(&body, "Label", unit.Label)
	writeLaunchdStringArray(&body, "ProgramArguments", unit.ProgramArguments)
	writeLaunchdString(&body, "UserName", unit.UserName)
	writeLaunchdString(&body, "GroupName", unit.GroupName)
	writeLaunchdBool(&body, "KeepAlive", unit.KeepAlive)
	writeLaunchdBool(&body, "RunAtLoad", unit.RunAtLoad)
	writeLaunchdInteger(&body, "ThrottleInterval", normalizedLaunchdThrottle(unit.ThrottleInterval))
	if unit.ProcessType != "" {
		writeLaunchdString(&body, "ProcessType", unit.ProcessType)
	}
	for _, optional := range []struct{ key, value string }{
		{"WorkingDirectory", unit.WorkingDirectory}, {"RootDirectory", unit.RootDirectory},
		{"StandardOutPath", unit.StandardOutPath}, {"StandardErrorPath", unit.StandardErrorPath},
	} {
		if optional.value != "" {
			writeLaunchdString(&body, optional.key, optional.value)
		}
	}
	writeLaunchdEnvironment(&body, unit.Environment)
	writeLaunchdSockets(&body, unit.Sockets)
	body.WriteString("</dict>\n</plist>\n")
	return body.String(), nil
}

func (unit LaunchdUnit) validate() error {
	if !validLaunchdLabel(unit.Label) {
		return errors.New("launchd label must be a reverse-DNS-style literal")
	}
	if err := validatex.AccountNames(map[string]string{"user": unit.UserName, "group": unit.GroupName}); err != nil {
		return err
	}
	validators := []func() error{
		func() error { return validateLaunchdArguments(unit.ProgramArguments) },
		func() error { return validateLaunchdRuntime(unit) },
		func() error { return validateLaunchdPaths(unit) },
		func() error { return validateLaunchdEnvironment(unit.Environment) },
		func() error { return validateLaunchdSockets(unit.Sockets) },
	}
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateLaunchdArguments(arguments []string) error {
	if len(arguments) == 0 || !filepath.IsAbs(arguments[0]) {
		return errors.New("launchd program must be an absolute path")
	}
	for _, argument := range arguments {
		if argument == "" || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("launchd program arguments must be non-empty single-line values")
		}
	}
	return nil
}

func validateLaunchdRuntime(unit LaunchdUnit) error {
	validProcessTypes := map[string]struct{}{"": {}, "Background": {}, "Standard": {}, "Interactive": {}, "Adaptive": {}}
	if _, valid := validProcessTypes[unit.ProcessType]; !valid {
		return errors.New("launchd process type is invalid")
	}
	if unit.ThrottleInterval < 0 {
		return errors.New("launchd throttle interval must not be negative")
	}
	return nil
}

func validateLaunchdPaths(unit LaunchdUnit) error {
	values := map[string]string{}
	for key, value := range map[string]string{
		"working directory": unit.WorkingDirectory, "root directory": unit.RootDirectory,
		"standard output path": unit.StandardOutPath, "standard error path": unit.StandardErrorPath,
	} {
		if value != "" {
			values[key] = value
		}
	}
	return validatex.AbsolutePaths(values, true)
}

func validateLaunchdEnvironment(values map[string]string) error {
	for key, value := range values {
		if !validEnvironmentName(key) || strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("launchd environment variable %q is invalid", key)
		}
	}
	return nil
}

func validateLaunchdSockets(sockets []LaunchdSocket) error {
	if len(sockets) == 0 {
		return errors.New("launchd unit requires at least one named socket")
	}
	seenNames, seenPaths := map[string]struct{}{}, map[string]struct{}{}
	for _, socket := range sockets {
		if err := validateLaunchdSocket(socket, seenNames, seenPaths); err != nil {
			return err
		}
	}
	return nil
}

func validateLaunchdSocket(socket LaunchdSocket, seenNames, seenPaths map[string]struct{}) error {
	if !validName(socket.Name) {
		return errors.New("launchd socket name is invalid")
	}
	if err := rememberLaunchdSocketName(socket.Name, seenNames); err != nil {
		return err
	}
	if err := rememberLaunchdSocketPath(socket.Path, seenPaths); err != nil {
		return err
	}
	if err := validatex.AccountNames(map[string]string{"socket owner": socket.Owner, "socket group": socket.Group}); err != nil {
		return err
	}
	if err := validateSocketMode(socket.Mode, "launchd socket"); err != nil {
		return err
	}
	return validateSocketMode(socket.DirectoryMode, "launchd socket directory")
}

func rememberLaunchdSocketName(name string, seen map[string]struct{}) error {
	if _, exists := seen[name]; exists {
		return fmt.Errorf("launchd socket %q is duplicated", name)
	}
	seen[name] = struct{}{}
	return nil
}

func rememberLaunchdSocketPath(path string, seen map[string]struct{}) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return errors.New("launchd socket path must be absolute and normalized")
	}
	if _, exists := seen[path]; exists {
		return fmt.Errorf("launchd socket path %q is duplicated", path)
	}
	seen[path] = struct{}{}
	return nil
}

func validLaunchdLabel(value string) bool {
	return validName(value) && strings.Contains(value, ".") && !strings.HasPrefix(value, ".") && !strings.HasSuffix(value, ".")
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if !validEnvironmentCharacter(index, character) {
			return false
		}
	}
	return true
}

func validEnvironmentCharacter(index int, character rune) bool {
	if character >= 'A' && character <= 'Z' || character == '_' {
		return true
	}
	return index > 0 && character >= '0' && character <= '9'
}

func normalizedLaunchdThrottle(value int) int {
	if value == 0 {
		return 5
	}
	return value
}

func writeLaunchdKey(body *bytes.Buffer, key string) {
	body.WriteString("  <key>")
	_ = xml.EscapeText(body, []byte(key))
	body.WriteString("</key>\n")
}

func writeLaunchdString(body *bytes.Buffer, key, value string) {
	writeLaunchdKey(body, key)
	body.WriteString("  <string>")
	_ = xml.EscapeText(body, []byte(value))
	body.WriteString("</string>\n")
}

func writeLaunchdStringArray(body *bytes.Buffer, key string, values []string) {
	writeLaunchdKey(body, key)
	body.WriteString("  <array>\n")
	for _, value := range values {
		body.WriteString("    <string>")
		_ = xml.EscapeText(body, []byte(value))
		body.WriteString("</string>\n")
	}
	body.WriteString("  </array>\n")
}

func writeLaunchdBool(body *bytes.Buffer, key string, value bool) {
	writeLaunchdKey(body, key)
	if value {
		body.WriteString("  <true/>\n")
	} else {
		body.WriteString("  <false/>\n")
	}
}

func writeLaunchdInteger(body *bytes.Buffer, key string, value int) {
	writeLaunchdKey(body, key)
	_, _ = fmt.Fprintf(body, "  <integer>%d</integer>\n", value)
}

func writeLaunchdEnvironment(body *bytes.Buffer, values map[string]string) {
	if len(values) == 0 {
		return
	}
	writeLaunchdKey(body, "EnvironmentVariables")
	body.WriteString("  <dict>\n")
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		body.WriteString("    <key>")
		_ = xml.EscapeText(body, []byte(key))
		body.WriteString("</key>\n    <string>")
		_ = xml.EscapeText(body, []byte(values[key]))
		body.WriteString("</string>\n")
	}
	body.WriteString("  </dict>\n")
}

func writeLaunchdSockets(body *bytes.Buffer, sockets []LaunchdSocket) {
	writeLaunchdKey(body, "Sockets")
	body.WriteString("  <dict>\n")
	for _, socket := range sockets {
		body.WriteString("    <key>")
		_ = xml.EscapeText(body, []byte(socket.Name))
		body.WriteString("</key>\n    <dict>\n")
		for _, field := range []struct{ key, value string }{{"SockPathName", socket.Path}, {"SockPathOwner", socket.Owner}, {"SockPathGroup", socket.Group}} {
			body.WriteString("      <key>" + field.key + "</key>\n      <string>")
			_ = xml.EscapeText(body, []byte(field.value))
			body.WriteString("</string>\n")
		}
		body.WriteString("      <key>SockPathMode</key>\n")
		_, _ = fmt.Fprintf(body, "      <integer>%d</integer>\n", socket.Mode.Perm())
		body.WriteString("    </dict>\n")
	}
	body.WriteString("  </dict>\n")
}
