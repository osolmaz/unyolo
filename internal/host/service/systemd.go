// Package service renders provider-neutral broker service definitions.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"unicode"

	"github.com/osolmaz/brokerkit/internal/validatex"
)

// CommandRunner runs provider-neutral host setup commands.
type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

// SystemdUnit describes one broker-family systemd service.
type SystemdUnit struct {
	Description                  string
	User                         string
	Group                        string
	SupplementaryGroups          []string
	EnvironmentFile              string
	ExecStart                    string
	StateDir                     string
	ConfigDir                    string
	RestartSec                   int
	HomeAccess                   HomeAccess
	HostFilesystemAccess         HostFilesystemAccess
	PrivilegeEscalation          PrivilegeEscalation
	PathValidation               PathValidation
	ExtraDirectives              []string
	AfterUnits                   []string
	RequiresUnits                []string
	RuntimeDirectory             string
	RuntimeDirectoryMode         os.FileMode
	ManagedExecutableDestination string
}

// SystemdSocketUnit describes one deployment-owned listening socket. The
// socket is passed to Service with FileDescriptorName when it is activated.
type SystemdSocketUnit struct {
	Description        string
	ListenStream       string
	Service            string
	FileDescriptorName string
	SocketUser         string
	SocketGroup        string
	SocketMode         os.FileMode
	DirectoryMode      os.FileMode
}

// SystemdSocketInstall binds a socket unit filename to its typed definition.
type SystemdSocketInstall struct {
	UnitName string
	Unit     SystemdSocketUnit
}

// RenderSystemdSocket renders a permission-scoped stream socket unit.
func RenderSystemdSocket(unit SystemdSocketUnit) (string, error) {
	if err := unit.validate(); err != nil {
		return "", err
	}
	return fmt.Sprintf(`[Unit]
Description=%s

[Socket]
ListenStream=%s
FileDescriptorName=%s
SocketUser=%s
SocketGroup=%s
SocketMode=%04o
DirectoryMode=%04o
Service=%s
RemoveOnStop=true

[Install]
WantedBy=sockets.target
`, unit.Description, unit.ListenStream, unit.FileDescriptorName, unit.SocketUser,
		unit.SocketGroup, unit.SocketMode.Perm(), unit.DirectoryMode.Perm(), unit.Service), nil
}

// RenderSystemdSockets renders named socket units for dry-run output.
func RenderSystemdSockets(units []SystemdSocketInstall) (string, error) {
	var body strings.Builder
	for _, unit := range units {
		rendered, err := RenderSystemdSocket(unit.Unit)
		if err != nil {
			return "", fmt.Errorf("render %s: %w", unit.UnitName, err)
		}
		_, _ = fmt.Fprintf(&body, "\n# %s\n%s", unit.UnitName, rendered)
	}
	return body.String(), nil
}

func (unit SystemdSocketUnit) validate() error {
	if err := validateRequiredLines(map[string]string{
		"description": unit.Description, "listen stream": unit.ListenStream,
		"service": unit.Service, "file descriptor name": unit.FileDescriptorName,
		"socket user": unit.SocketUser, "socket group": unit.SocketGroup,
	}); err != nil {
		return err
	}
	validators := []func() error{
		func() error { return validateDescription(unit.Description) },
		func() error { return validateSystemdSocketAddress(unit) },
		func() error {
			return validatex.AccountNames(map[string]string{"socket user": unit.SocketUser, "socket group": unit.SocketGroup})
		},
		func() error { return validateSocketMode(unit.SocketMode, "socket") },
		func() error { return validateSocketDirectoryMode(unit.DirectoryMode, "socket directory") },
	}
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateSystemdSocketAddress(unit SystemdSocketUnit) error {
	if !filepath.IsAbs(unit.ListenStream) || filepath.Clean(unit.ListenStream) != unit.ListenStream || unit.ListenStream == string(filepath.Separator) {
		return errors.New("systemd socket listen path must be absolute and normalized")
	}
	if !validDependencyUnit(unit.Service) || !strings.HasSuffix(unit.Service, ".service") {
		return errors.New("systemd socket service must be a literal .service unit name")
	}
	if !validName(unit.FileDescriptorName) {
		return errors.New("systemd socket descriptor name is invalid")
	}
	return nil
}

func validateSocketMode(mode os.FileMode, label string) error {
	if mode == 0 || mode&^os.ModePerm != 0 || mode.Perm()&0o007 != 0 {
		return fmt.Errorf("%s mode must deny all access to other users", label)
	}
	return nil
}

func validateSocketDirectoryMode(mode os.FileMode, label string) error {
	if mode == 0 || mode&^os.ModePerm != 0 || mode.Perm()&0o700 != 0o700 || mode.Perm()&0o022 != 0 {
		return fmt.Errorf("%s mode must be owner-accessible and not writable by other users", label)
	}
	return nil
}

func validName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, char := range value {
		if !unicode.IsLetter(char) && !unicode.IsDigit(char) && !strings.ContainsRune("_.-", char) {
			return false
		}
	}
	return true
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

// HostFilesystemAccess controls whether the service may write outside its
// declared state and home paths. The zero value keeps the host read-only.
type HostFilesystemAccess string

const (
	HostFilesystemAccessDeny  HostFilesystemAccess = "deny"
	HostFilesystemAccessAllow HostFilesystemAccess = "allow"
)

// PathValidation controls filesystem trust checks while rendering a unit.
type PathValidation string

const (
	// PathValidationStrict is the default for units that may be installed.
	PathValidationStrict PathValidation = "strict"
	// PathValidationPreview skips host trust checks for dry-runs and non-root fixtures.
	PathValidationPreview PathValidation = "preview"
)

// PrivilegeEscalation controls whether the service may perform a deliberate
// setuid transition. The zero value denies privilege escalation.
type PrivilegeEscalation string

const (
	PrivilegeEscalationDeny  PrivilegeEscalation = "deny"
	PrivilegeEscalationAllow PrivilegeEscalation = "allow"
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

var (
	lookupSystemUser     = user.Lookup
	lookupSystemGroup    = user.LookupGroup
	lookupSystemGroupIDs = func(account *user.User) ([]string, error) { return account.GroupIds() }
)

// RenderSystemd renders a hardened systemd unit using the shared broker-family
// baseline. Broker-specific directives may be appended to the Service section.
func RenderSystemd(unit SystemdUnit) (string, error) {
	if err := unit.validate(); err != nil {
		return "", err
	}
	restartSec := normalizedRestartSec(unit.RestartSec)
	protectHome := protectHomeValue(unit.HomeAccess)
	protectSystem, readWritePaths, noNewPrivileges := systemdProtectionValues(unit)
	after := append([]string{"network-online.target"}, unit.AfterUnits...)
	var body strings.Builder
	_, _ = fmt.Fprintf(&body, "[Unit]\nDescription=%s\nAfter=%s\nWants=network-online.target\n", unit.Description, strings.Join(after, " "))
	writeUnitValues(&body, "Requires", unit.RequiresUnits)
	_, _ = fmt.Fprintf(&body, `
[Service]
Type=simple
User=%s
Group=%s
`, unit.User, unit.Group)
	writeUnitValues(&body, "SupplementaryGroups", unit.SupplementaryGroups)
	_, _ = fmt.Fprintf(&body, `
EnvironmentFile=%s
ExecStart=%s
Restart=on-failure
RestartSec=%d
NoNewPrivileges=%s
PrivateTmp=true
ProtectSystem=%s
ProtectHome=%s
ReadWritePaths=%s
ReadOnlyPaths=%s
`, unit.EnvironmentFile, unit.ExecStart, restartSec, noNewPrivileges, protectSystem, protectHome, readWritePaths, unit.ConfigDir)
	writeRuntimeDirectory(&body, unit.RuntimeDirectory, unit.RuntimeDirectoryMode)
	for _, directive := range unit.ExtraDirectives {
		body.WriteString(directive)
		body.WriteByte('\n')
	}
	body.WriteString("\n[Install]\nWantedBy=multi-user.target\n")
	return body.String(), nil
}

func normalizedRestartSec(value int) int {
	if value <= 0 {
		return 5
	}
	return value
}

func systemdProtectionValues(unit SystemdUnit) (string, string, string) {
	protectSystem := "strict"
	if normalizedHostFilesystemAccess(unit.HostFilesystemAccess) == HostFilesystemAccessAllow {
		protectSystem = "false"
	}
	readWritePaths := unit.StateDir
	if normalizedHomeAccess(unit.HomeAccess) == HomeAccessAllow {
		readWritePaths += " -/home -/root -/run/user"
	}
	noNewPrivileges := "true"
	if normalizedPrivilegeEscalation(unit.PrivilegeEscalation) == PrivilegeEscalationAllow {
		noNewPrivileges = "false"
	}
	return protectSystem, readWritePaths, noNewPrivileges
}

func writeUnitValues(body *strings.Builder, directive string, values []string) {
	if len(values) > 0 {
		_, _ = fmt.Fprintf(body, "%s=%s\n", directive, strings.Join(values, " "))
	}
}

func writeRuntimeDirectory(body *strings.Builder, directory string, mode os.FileMode) {
	if directory == "" {
		return
	}
	if mode == 0 {
		mode = 0o750
	}
	_, _ = fmt.Fprintf(body, "RuntimeDirectory=%s\nRuntimeDirectoryMode=%04o\n", directory, mode.Perm())
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
	checks := []func() error{
		func() error { return validateRequiredLines(values) },
		func() error { return validateDescription(unit.Description) },
		func() error { return validatex.AccountNames(map[string]string{"user": unit.User, "group": unit.Group}) },
		func() error { return validateSupplementaryGroups(unit.SupplementaryGroups) },
		func() error { return validateSystemdPolicies(unit) },
		func() error { return validateSystemdUnitPaths(unit) },
		func() error { return validateManagedExecutableReference(unit) },
		func() error { return validateUnitDependencies(unit) },
		func() error { return validateExtraDirectives(unit.ExtraDirectives) },
	}
	for _, check := range checks {
		if err := check(); err != nil {
			return err
		}
	}
	return nil
}

func validateSupplementaryGroups(groups []string) error {
	values := make(map[string]string, len(groups))
	for index, group := range groups {
		values[fmt.Sprintf("supplementary group %d", index+1)] = group
	}
	return validatex.AccountNames(values)
}

func validateUnitDependencies(unit SystemdUnit) error {
	dependencies := append(append([]string(nil), unit.AfterUnits...), unit.RequiresUnits...)
	if err := validateDependencyNames(dependencies); err != nil {
		return err
	}
	return validateRuntimeDirectory(unit.RuntimeDirectory, unit.RuntimeDirectoryMode)
}

func validateDependencyNames(dependencies []string) error {
	for _, name := range dependencies {
		if !validDependencyUnit(name) {
			return fmt.Errorf("systemd dependency %q is invalid", name)
		}
	}
	return nil
}

func validateRuntimeDirectory(directory string, mode os.FileMode) error {
	if directory == "" {
		if mode != 0 {
			return errors.New("runtime directory mode requires a runtime directory")
		}
		return nil
	}
	if filepath.Base(directory) != directory || !validRuntimeDirectory(directory) {
		return errors.New("runtime directory must be one safe basename")
	}
	if mode == 0 {
		mode = 0o750
	}
	if !validRuntimeDirectoryMode(mode) {
		return errors.New("runtime directory mode must be private and owner-accessible")
	}
	return nil
}

func validRuntimeDirectoryMode(mode os.FileMode) bool {
	return mode.Perm()&0o007 == 0 && mode.Perm()&0o700 != 0 && mode&^os.ModePerm == 0
}

func validDependencyUnit(value string) bool {
	if filepath.Base(value) != value || (!strings.HasSuffix(value, ".service") && !strings.HasSuffix(value, ".target")) {
		return false
	}
	for _, character := range value {
		if !validDependencyCharacter(character) {
			return false
		}
	}
	return true
}

func validDependencyCharacter(character rune) bool {
	return asciiLetter(character) || asciiDigit(character) || strings.ContainsRune("_.@-", character)
}

func validRuntimeDirectory(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !validRuntimeDirectoryCharacter(character) {
			return false
		}
	}
	return true
}

func validRuntimeDirectoryCharacter(character rune) bool {
	return asciiLower(character) || asciiDigit(character) || character == '-' || character == '_'
}

func asciiLetter(character rune) bool {
	return asciiLower(character) || (character >= 'A' && character <= 'Z')
}

func asciiLower(character rune) bool { return character >= 'a' && character <= 'z' }

func asciiDigit(character rune) bool { return character >= '0' && character <= '9' }

func validateSystemdPolicies(unit SystemdUnit) error {
	validators := []func() error{
		func() error { return validateHomeAccess(unit.HomeAccess) },
		func() error { return validateHostFilesystemAccess(unit.HostFilesystemAccess) },
		func() error { return validatePrivilegeEscalation(unit.PrivilegeEscalation) },
		func() error { return validatePathValidation(unit.PathValidation) },
	}
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateHostFilesystemAccess(value HostFilesystemAccess) error {
	return validatePolicyValue("host filesystem access", string(value), string(normalizedHostFilesystemAccess(value)), string(HostFilesystemAccessDeny), string(HostFilesystemAccessAllow))
}

func normalizedHostFilesystemAccess(value HostFilesystemAccess) HostFilesystemAccess {
	if value == "" {
		return HostFilesystemAccessDeny
	}
	return value
}

func validateDescription(value string) error {
	if strings.HasSuffix(value, "\\") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return errors.New("description contains unsupported systemd syntax")
	}
	return nil
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
	if strings.ContainsAny(value, "%\\\"'$;") || strings.IndexFunc(value, unicode.IsControl) >= 0 {
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
		if err := validateProtectedServicePath(name, value); err != nil {
			return err
		}
	}
	if filepath.Clean(unit.StateDir) == string(filepath.Separator) {
		return errors.New("state directory must not make the filesystem root writable")
	}
	if normalizedPathValidation(unit.PathValidation) == PathValidationStrict {
		if err := validateTrustedServicePaths(unit); err != nil {
			return err
		}
	}
	return validateServicePathIsolation(unit)
}

func validatePathValidation(value PathValidation) error {
	return validatePolicyValue("path validation", string(value), string(normalizedPathValidation(value)), string(PathValidationStrict), string(PathValidationPreview))
}

func normalizedPathValidation(value PathValidation) PathValidation {
	if value == "" {
		return PathValidationStrict
	}
	return value
}

func validateTrustedServicePaths(unit SystemdUnit) error {
	paths := map[string]struct {
		value      string
		finalOwner string
	}{
		"environment file": {value: unit.EnvironmentFile},
		"config directory": {value: unit.ConfigDir},
		"state directory":  {value: unit.StateDir, finalOwner: unit.User},
	}
	for name, path := range paths {
		if err := validateTrustedServicePath(name, path.value, path.finalOwner); err != nil {
			return err
		}
	}
	if unit.ManagedExecutableDestination != "" {
		return validateManagedExecutableAccess(unit)
	}
	executable := strings.SplitN(unit.ExecStart, " ", 2)[0]
	if err := validateTrustedServicePath("executable", executable, ""); err != nil {
		return err
	}
	return validateTrustedExecutableAccess(unit)
}

func identityCanExecute(mode os.FileMode, ownerUID uint64, ownerGID uint64, uid uint64, gid uint64) bool {
	return identityCanExecuteWithGroups(mode, ownerUID, ownerGID, uid, map[uint64]struct{}{gid: {}})
}

func identityCanExecuteWithGroups(mode os.FileMode, ownerUID uint64, ownerGID uint64, uid uint64, groupIDs map[uint64]struct{}) bool {
	if uid == 0 {
		return mode&0o111 != 0
	}
	return identityPermission(mode, ownerUID, ownerGID, uid, groupIDs, 0o100, 0o010, 0o001)
}

func identityCanSearch(mode os.FileMode, ownerUID uint64, ownerGID uint64, uid uint64, groupIDs map[uint64]struct{}) bool {
	if uid == 0 {
		return true
	}
	return identityPermission(mode, ownerUID, ownerGID, uid, groupIDs, 0o100, 0o010, 0o001)
}

func identityPermission(mode os.FileMode, ownerUID uint64, ownerGID uint64, uid uint64, groupIDs map[uint64]struct{}, ownerBit os.FileMode, groupBit os.FileMode, otherBit os.FileMode) bool {
	switch {
	case uid == ownerUID:
		return mode&ownerBit != 0
	case identityHasGroup(groupIDs, ownerGID):
		return mode&groupBit != 0
	default:
		return mode&otherBit != 0
	}
}

func identityHasGroup(groupIDs map[uint64]struct{}, gid uint64) bool {
	_, ok := groupIDs[gid]
	return ok
}

func validateTrustedServicePath(name string, path string, finalOwner string) error {
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect %s path: %w", name, err)
		}
		final := index == len(components)-1
		expectedOwner := ""
		if final {
			expectedOwner = finalOwner
		}
		if err := validateTrustedServiceComponent(name, current, info, expectedOwner); err != nil {
			return err
		}
	}
	return nil
}

func validateTrustedServiceComponent(name string, path string, info os.FileInfo, expectedOwner string) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s path must not contain symbolic links: %s", name, path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s path ownership is unavailable: %s", name, path)
	}
	if err := validateTrustedServiceOwner(name, path, uint64(stat.Uid), expectedOwner); err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s path component must not be mutable by untrusted users: %s", name, path)
	}
	return nil
}

func validateTrustedServiceOwner(name string, path string, actualUID uint64, expectedOwner string) error {
	if expectedOwner == "" {
		if actualUID != 0 {
			return fmt.Errorf("%s path component must be root-owned: %s", name, path)
		}
		return nil
	}
	expectedUID, err := systemUserUID(expectedOwner)
	if err != nil {
		return fmt.Errorf("resolve %s owner: %w", name, err)
	}
	if actualUID != expectedUID {
		return fmt.Errorf("%s must be owned by service user %s: %s", name, expectedOwner, path)
	}
	return nil
}

func systemUserUID(name string) (uint64, error) {
	account, err := lookupSystemUser(name)
	if err != nil {
		return 0, fmt.Errorf("lookup user %q: %w", name, err)
	}
	uid, err := parseSystemID("uid", name, account.Uid)
	if err != nil {
		return 0, err
	}
	return uid, nil
}

func validateProtectedServicePath(name string, value string) error {
	if err := validateSystemdPath(name, value); err != nil {
		return err
	}
	if validatex.HasParentTraversal(value) {
		return fmt.Errorf("%s must not contain parent traversal", name)
	}
	if protectedHomePath(value) {
		return fmt.Errorf("%s must not be under a mutable user-home path", name)
	}
	return nil
}

func validateServicePathIsolation(unit SystemdUnit) error {
	stateDir := filepath.Clean(unit.StateDir)
	configDir := filepath.Clean(unit.ConfigDir)
	if pathsOverlap(stateDir, configDir) {
		return errors.New("state and config directories must not overlap")
	}
	for name, value := range map[string]string{
		"environment file": unit.EnvironmentFile,
		"executable":       strings.SplitN(unit.ExecStart, " ", 2)[0],
	} {
		if pathWithin(stateDir, filepath.Clean(value)) {
			return fmt.Errorf("%s must not be inside the writable state directory", name)
		}
	}
	return nil
}

func pathsOverlap(left string, right string) bool {
	return pathWithin(left, right) || pathWithin(right, left)
}

func pathWithin(parent string, candidate string) bool {
	if parent == string(filepath.Separator) {
		return strings.HasPrefix(candidate, string(filepath.Separator))
	}
	return candidate == parent || strings.HasPrefix(candidate, parent+string(filepath.Separator))
}

func validateHomeAccess(value HomeAccess) error {
	return validatePolicyValue("home access", string(value), string(normalizedHomeAccess(value)), string(HomeAccessDeny), string(HomeAccessReadOnly), string(HomeAccessAllow))
}

func validatePrivilegeEscalation(value PrivilegeEscalation) error {
	return validatePolicyValue("privilege escalation", string(value), string(normalizedPrivilegeEscalation(value)), string(PrivilegeEscalationDeny), string(PrivilegeEscalationAllow))
}

func validatePolicyValue(name string, raw string, normalized string, allowed ...string) error {
	for _, value := range allowed {
		if normalized == value {
			return nil
		}
	}
	return fmt.Errorf("%s %q is invalid", name, raw)
}

func normalizedPrivilegeEscalation(value PrivilegeEscalation) PrivilegeEscalation {
	if value == "" {
		return PrivilegeEscalationDeny
	}
	return value
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
	return char == '/' || isPortableManagedFileNameCharacter(char)
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
