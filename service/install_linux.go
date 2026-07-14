//go:build linux

package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/osolmaz/brokerkit/internal/validatex"
)

const (
	maxManagedFileBytes      = 16 * 1024 * 1024
	defaultReadinessTimeout  = 15 * time.Second
	defaultReadinessInterval = 100 * time.Millisecond
)

var errServiceReadinessFailed = errors.New("service readiness check failed before retiring managed files")

// ManagedFileArea selects the trusted root beneath which a setup file lives.
type ManagedFileArea string

const (
	ManagedFileConfig ManagedFileArea = "config"
	ManagedFileState  ManagedFileArea = "state"
)

// ManagedFileOwner selects the ownership class for a setup file.
type ManagedFileOwner string

const (
	ManagedFileOwnerRoot    ManagedFileOwner = "root"
	ManagedFileOwnerService ManagedFileOwner = "service"
)

// ManagedFile is one opaque provider-owned setup payload.
type ManagedFile struct {
	Area  ManagedFileArea
	Name  string
	Data  []byte
	Mode  os.FileMode
	Owner ManagedFileOwner
}

// ManagedFileRef identifies one provider-owned file that should no longer
// exist after a successful configuration cutover.
type ManagedFileRef struct {
	Area ManagedFileArea
	Name string
}

// ReadinessCheck confirms that a restarted broker initialized with its new
// configuration before retired credentials are deleted.
type ReadinessCheck func(context.Context) error

// SystemdInstallPlan describes one complete broker systemd installation.
type SystemdInstallPlan struct {
	User             string
	Group            string
	AdditionalGroups []string
	GroupMembers     map[string][]string
	ConfigDir        string
	StateDir         string
	SharedStateDir   string
	SystemdDir       string
	UnitName         string
	Files            []ManagedFile
	RemoveFiles      []ManagedFileRef
	ReadyCheck       ReadinessCheck
	ReadyTimeout     time.Duration
	ReadyInterval    time.Duration
	Unit             SystemdUnit
	SocketUnits      []SystemdSocketInstall
	ActivationUnits  []string
	NoStart          bool
	AllowNonRoot     bool
	Runner           CommandRunner
}

// InstallSystemd installs one broker service from a validated typed plan.
func InstallSystemd(ctx context.Context, plan SystemdInstallPlan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := validateInstallPrivileges(plan); err != nil {
		return err
	}
	runner := installCommandRunner(plan)
	if err := ensureSystemAccount(ctx, runner, plan); err != nil {
		return err
	}
	if err := ensureAccessGroups(ctx, runner, plan); err != nil {
		return err
	}
	serviceUID, serviceGID, err := systemIdentityIDs(plan.User, plan.Group)
	if err != nil {
		return err
	}
	if err := validateNonRootIdentity(plan, serviceUID, serviceGID); err != nil {
		return err
	}
	return installSystemdForIdentity(ctx, runner, plan, serviceUID, serviceGID)
}

func validateInstallPrivileges(plan SystemdInstallPlan) error {
	if os.Geteuid() != 0 && !plan.AllowNonRoot {
		return errors.New("systemd installation must run as root")
	}
	return nil
}

func installCommandRunner(plan SystemdInstallPlan) CommandRunner {
	if plan.Runner != nil {
		return plan.Runner
	}
	return execCommandRunner{}
}

func installSystemdForIdentity(ctx context.Context, runner CommandRunner, plan SystemdInstallPlan, serviceUID uint64, serviceGID uint64) error {
	roots, err := prepareInstallRoots(plan, serviceUID, serviceGID)
	if err != nil {
		return err
	}
	defer roots.close()
	steps := []func() error{
		func() error { return writeManagedFiles(roots, plan, serviceUID, serviceGID) },
		func() error { return writeSystemdUnits(roots.systemd, plan) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	if err := startInstalledSystemdUnit(ctx, runner, plan); err != nil {
		return err
	}
	if plan.NoStart {
		return nil
	}
	if err := waitForSystemdReady(ctx, plan); err != nil {
		return err
	}
	return removeManagedFiles(roots, plan.RemoveFiles)
}

func startInstalledSystemdUnit(ctx context.Context, runner CommandRunner, plan SystemdInstallPlan) error {
	if plan.NoStart {
		return nil
	}
	units := plan.ActivationUnits
	if len(units) == 0 {
		units = []string{plan.UnitName}
	}
	return activateSystemdUnits(ctx, runner, units)
}

// Validate validates a systemd install plan without mutating the host.
func (plan SystemdInstallPlan) Validate() error {
	if err := validateInstallFields(plan); err != nil {
		return err
	}
	if err := validateInstallPaths(plan); err != nil {
		return err
	}
	if err := validateInstallUnit(plan); err != nil {
		return err
	}
	return validateManagedFiles(plan)
}

func validateInstallFields(plan SystemdInstallPlan) error {
	if err := validatex.AccountNames(map[string]string{"user": plan.User, "group": plan.Group}); err != nil {
		return err
	}
	if err := validateAccessGroups(plan); err != nil {
		return err
	}
	if !validUnitName(plan.UnitName) {
		return fmt.Errorf("systemd unit name %q must be a literal .service basename", plan.UnitName)
	}
	if plan.AllowNonRoot && !plan.NoStart {
		return errors.New("non-root test installation must disable service activation")
	}
	return validateReadinessSettings(plan)
}

func validateAccessGroups(plan SystemdInstallPlan) error {
	values := make(map[string]string, len(plan.AdditionalGroups))
	seen := map[string]struct{}{plan.Group: {}}
	for index, group := range plan.AdditionalGroups {
		values[fmt.Sprintf("additional group %d", index+1)] = group
		if _, exists := seen[group]; exists {
			return fmt.Errorf("duplicate system group %q", group)
		}
		seen[group] = struct{}{}
	}
	for group, members := range plan.GroupMembers {
		if _, exists := seen[group]; !exists {
			return fmt.Errorf("member group %q is not managed by this install plan", group)
		}
		for index, member := range members {
			values[fmt.Sprintf("%s member %d", group, index+1)] = member
		}
	}
	return validatex.AccountNames(values)
}

func validateReadinessSettings(plan SystemdInstallPlan) error {
	if plan.ReadyTimeout < 0 || plan.ReadyInterval < 0 {
		return errors.New("readiness timeout and interval must not be negative")
	}
	if len(plan.RemoveFiles) > 0 && !plan.NoStart && plan.ReadyCheck == nil {
		return errors.New("managed file retirement requires a readiness check")
	}
	return nil
}

func validUnitName(name string) bool {
	if !strings.HasSuffix(name, ".service") || filepath.Base(name) != name {
		return false
	}
	for _, char := range name {
		if !isUnitNameCharacter(char) {
			return false
		}
	}
	return true
}

func isUnitNameCharacter(char rune) bool {
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') || strings.ContainsRune("_.@-", char)
}

func validateInstallPaths(plan SystemdInstallPlan) error {
	paths := map[string]string{
		"config directory":  plan.ConfigDir,
		"state directory":   plan.StateDir,
		"systemd directory": plan.SystemdDir,
	}
	if err := validatex.AbsolutePaths(paths, false); err != nil {
		return err
	}
	if err := validateInstallPathValues(paths); err != nil {
		return err
	}
	if installRootsOverlap(plan) {
		return errors.New("config, state, and systemd directories must not overlap")
	}
	if err := validateSharedStateDir(plan); err != nil {
		return err
	}
	return nil
}

func validateSharedStateDir(plan SystemdInstallPlan) error {
	if plan.SharedStateDir == "" {
		return nil
	}
	if !validSharedStatePath(plan.SharedStateDir) {
		return errors.New("shared state directory must be an absolute normalized non-root path")
	}
	relative, err := filepath.Rel(plan.SharedStateDir, plan.StateDir)
	if err != nil || !isStrictDescendant(relative) {
		return errors.New("shared state directory must be a strict ancestor of the state directory")
	}
	return nil
}

func validSharedStatePath(path string) bool {
	return filepath.IsAbs(path) &&
		filepath.Clean(path) == path &&
		path != string(filepath.Separator)
}

func isStrictDescendant(relative string) bool {
	return relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateInstallPathValues(paths map[string]string) error {
	for name, path := range paths {
		if validatex.HasParentTraversal(path) {
			return fmt.Errorf("%s must not contain parent traversal", name)
		}
		if filepath.Clean(path) == string(filepath.Separator) {
			return fmt.Errorf("%s must not be the filesystem root", name)
		}
	}
	return nil
}

func installRootsOverlap(plan SystemdInstallPlan) bool {
	config := filepath.Clean(plan.ConfigDir)
	state := filepath.Clean(plan.StateDir)
	systemd := filepath.Clean(plan.SystemdDir)
	return pathsOverlap(config, state) || pathsOverlap(config, systemd) || pathsOverlap(state, systemd)
}

func validateInstallUnit(plan SystemdInstallPlan) error {
	if plan.Unit.User != plan.User || plan.Unit.Group != plan.Group {
		return errors.New("systemd unit identity must match install plan")
	}
	if filepath.Clean(plan.Unit.ConfigDir) != filepath.Clean(plan.ConfigDir) ||
		filepath.Clean(plan.Unit.StateDir) != filepath.Clean(plan.StateDir) {
		return errors.New("systemd unit directories must match install plan")
	}
	preview := plan.Unit
	preview.PathValidation = PathValidationPreview
	if _, err := RenderSystemd(preview); err != nil {
		return err
	}
	return validateSocketInstallUnits(plan)
}

func validateSocketInstallUnits(plan SystemdInstallPlan) error {
	seen := map[string]struct{}{plan.UnitName: {}}
	for _, socket := range plan.SocketUnits {
		if !validSocketUnitName(socket.UnitName) {
			return fmt.Errorf("systemd socket unit name %q must be a literal .socket basename", socket.UnitName)
		}
		if _, exists := seen[socket.UnitName]; exists {
			return fmt.Errorf("duplicate systemd unit name %q", socket.UnitName)
		}
		seen[socket.UnitName] = struct{}{}
		if socket.Unit.Service != plan.UnitName {
			return fmt.Errorf("systemd socket unit %q targets an unmanaged service", socket.UnitName)
		}
		if _, err := RenderSystemdSocket(socket.Unit); err != nil {
			return fmt.Errorf("render %s: %w", socket.UnitName, err)
		}
	}
	for _, name := range plan.ActivationUnits {
		if _, exists := seen[name]; !exists {
			return fmt.Errorf("activation unit %q is not managed by this plan", name)
		}
	}
	return nil
}

func validSocketUnitName(name string) bool {
	return strings.HasSuffix(name, ".socket") && filepath.Base(name) == name && validUnitNameCharacters(name)
}

func validUnitNameCharacters(name string) bool {
	for _, char := range name {
		if !isUnitNameCharacter(char) {
			return false
		}
	}
	return true
}

func validateManagedFiles(plan SystemdInstallPlan) error {
	seen := make(map[string]struct{}, len(plan.Files)+len(plan.RemoveFiles))
	environmentManaged, err := validateManagedFileWrites(plan, seen)
	if err != nil {
		return err
	}
	if err := validateManagedFileRemovals(plan, seen); err != nil {
		return err
	}
	if !environmentManaged {
		return errors.New("systemd environment file must be a managed file")
	}
	return nil
}

func validateManagedFileWrites(plan SystemdInstallPlan, seen map[string]struct{}) (bool, error) {
	environmentManaged := false
	for _, file := range plan.Files {
		if err := validateManagedFile(plan, file); err != nil {
			return false, err
		}
		key := managedFileKey(file.Area, file.Name)
		if _, exists := seen[key]; exists {
			return false, fmt.Errorf("duplicate managed file %s", key)
		}
		seen[key] = struct{}{}
		if filepath.Clean(managedFilePath(plan, file)) == filepath.Clean(plan.Unit.EnvironmentFile) {
			if file.Owner != ManagedFileOwnerRoot {
				return false, errors.New("systemd environment file must be root-owned")
			}
			environmentManaged = true
		}
	}
	return environmentManaged, nil
}

func validateManagedFileRemovals(plan SystemdInstallPlan, seen map[string]struct{}) error {
	for _, file := range plan.RemoveFiles {
		if err := validateManagedFileRef(file); err != nil {
			return err
		}
		key := managedFileKey(file.Area, file.Name)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate managed file %s", key)
		}
		if filepath.Clean(managedFileRefPath(plan, file)) == filepath.Clean(plan.Unit.EnvironmentFile) {
			return errors.New("systemd environment file must be written, not removed")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateManagedFile(plan SystemdInstallPlan, file ManagedFile) error {
	if err := validateManagedFilePlacement(file); err != nil {
		return err
	}
	if err := validateManagedFilePayload(file); err != nil {
		return err
	}
	return validateManagedFilePermissions(plan, file)
}

func validateManagedFilePlacement(file ManagedFile) error {
	if !validManagedFileName(file.Name) {
		return fmt.Errorf("managed file name %q must be a literal direct child", file.Name)
	}
	if err := validateManagedFileArea(file.Area, file.Name); err != nil {
		return err
	}
	if file.Owner != ManagedFileOwnerRoot && file.Owner != ManagedFileOwnerService {
		return fmt.Errorf("managed file %q has invalid owner %q", file.Name, file.Owner)
	}
	return nil
}

func validateManagedFileRef(file ManagedFileRef) error {
	if !validManagedFileName(file.Name) {
		return fmt.Errorf("managed file name %q must be a literal direct child", file.Name)
	}
	if file.Area != ManagedFileConfig {
		return fmt.Errorf("retired managed file %q must be in the config area", file.Name)
	}
	return nil
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, name string, args ...string) error {
	return exec.CommandContext(ctx, name, args...).Run() // #nosec G204 -- command names and arguments are fixed setup primitives.
}

func ensureSystemAccount(ctx context.Context, runner CommandRunner, plan SystemdInstallPlan) error {
	if runner.Run(ctx, "getent", "group", plan.Group) != nil {
		if err := runner.Run(ctx, "groupadd", "--system", plan.Group); err != nil {
			return fmt.Errorf("create service group %q: %w", plan.Group, err)
		}
	}
	if runner.Run(ctx, "id", "-u", plan.User) == nil {
		return nil
	}
	if err := runner.Run(ctx, "useradd", "--system", "--gid", plan.Group, "--home-dir", plan.StateDir, "--shell", "/usr/sbin/nologin", plan.User); err != nil {
		return fmt.Errorf("create service user %q: %w", plan.User, err)
	}
	return nil
}

func ensureAccessGroups(ctx context.Context, runner CommandRunner, plan SystemdInstallPlan) error {
	for _, group := range plan.AdditionalGroups {
		if runner.Run(ctx, "getent", "group", group) != nil {
			if err := runner.Run(ctx, "groupadd", "--system", group); err != nil {
				return fmt.Errorf("create access group %q: %w", group, err)
			}
		}
		for _, member := range plan.GroupMembers[group] {
			if runner.Run(ctx, "id", "-u", member) != nil {
				return fmt.Errorf("access group member %q does not exist", member)
			}
			if err := runner.Run(ctx, "usermod", "--append", "--groups", group, member); err != nil {
				return fmt.Errorf("add %q to access group %q: %w", member, group, err)
			}
		}
	}
	return nil
}

func validateNonRootIdentity(plan SystemdInstallPlan, uid uint64, gid uint64) error {
	if !plan.AllowNonRoot {
		return nil
	}
	currentUID, currentGID, err := currentInstallIDs()
	if err != nil {
		return err
	}
	if uid != currentUID || gid != currentGID {
		return errors.New("non-root test installation must use the current user and group")
	}
	return nil
}

type installRoots struct {
	config  *os.Root
	state   *os.Root
	systemd *os.Root
}

func prepareInstallRoots(plan SystemdInstallPlan, serviceUID uint64, serviceGID uint64) (installRoots, error) {
	rootUID, rootGID := installRootIDs(plan)
	if plan.SharedStateDir != "" {
		if err := prepareInstallDirectory(plan.SharedStateDir, 0o750, rootUID, serviceGID, plan.AllowNonRoot, false); err != nil {
			return installRoots{}, fmt.Errorf("prepare shared state directory: %w", err)
		}
	}
	if err := prepareInstallDirectory(plan.ConfigDir, 0o750, rootUID, serviceGID, plan.AllowNonRoot, false); err != nil {
		return installRoots{}, fmt.Errorf("prepare config directory: %w", err)
	}
	if err := prepareInstallDirectory(plan.StateDir, 0o750, serviceUID, serviceGID, plan.AllowNonRoot, true); err != nil {
		return installRoots{}, fmt.Errorf("prepare state directory: %w", err)
	}
	if err := prepareInstallDirectory(plan.SystemdDir, 0o755, rootUID, rootGID, plan.AllowNonRoot, false); err != nil {
		return installRoots{}, fmt.Errorf("prepare systemd directory: %w", err)
	}
	return openInstallRoots(plan)
}

func installRootIDs(plan SystemdInstallPlan) (uint64, uint64) {
	if plan.AllowNonRoot {
		uid, gid, err := currentInstallIDs()
		if err == nil {
			return uid, gid
		}
	}
	return 0, 0
}

func currentInstallIDs() (uint64, uint64, error) {
	uid := os.Getuid()
	gid := os.Getgid()
	if uid < 0 || gid < 0 {
		return 0, 0, errors.New("current Unix identity is invalid")
	}
	return uint64(uid), uint64(gid), nil // #nosec G115 -- nonnegative Unix IDs are checked above.
}

func prepareInstallDirectory(path string, mode os.FileMode, uid uint64, gid uint64, preview bool, allowServiceOwner bool) error {
	if err := ensureInstallDirectory(path, uid, preview, allowServiceOwner); err != nil {
		return err
	}
	root, err := openVerifiedInstallRoot(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return setInstallRootMetadata(root, mode, uid, gid, preview)
}

func ensureInstallDirectory(path string, finalUID uint64, preview bool, allowServiceOwner bool) error {
	if preview {
		if err := os.MkdirAll(path, 0o750); err != nil {
			return err
		}
		return inspectInstallDirectoryPath(path)
	}
	return createTrustedInstallDirectoryPath(path, finalUID, allowServiceOwner)
}

func createTrustedInstallDirectoryPath(path string, finalUID uint64, allowServiceOwner bool) error {
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for index, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o750); err != nil {
				return fmt.Errorf("create %s: %w", current, err)
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return fmt.Errorf("inspect %s: %w", current, err)
		}
		final := index == len(components)-1
		if err := validateInstallDirectoryComponent(current, info, final, finalUID, allowServiceOwner); err != nil {
			return err
		}
	}
	return nil
}

func inspectInstallDirectoryPath(path string) error {
	components := strings.Split(strings.TrimPrefix(filepath.Clean(path), string(filepath.Separator)), string(filepath.Separator))
	current := string(filepath.Separator)
	for _, component := range components {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("install path must contain only real directories: %s", current)
		}
	}
	return nil
}

func validateInstallDirectoryComponent(path string, info os.FileInfo, final bool, finalUID uint64, allowServiceOwner bool) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("install path must contain only real directories: %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("install path ownership is unavailable: %s", path)
	}
	if !trustedInstallDirectoryOwner(uint64(stat.Uid), final, finalUID, allowServiceOwner) {
		return fmt.Errorf("install path component has an untrusted owner: %s", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("install path component is mutable by group or other: %s", path)
	}
	return nil
}

func trustedInstallDirectoryOwner(ownerUID uint64, final bool, finalUID uint64, allowServiceOwner bool) bool {
	return ownerUID == 0 || final && allowServiceOwner && ownerUID == finalUID
}

func openVerifiedInstallRoot(path string) (*os.Root, error) {
	expected, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(expected, actual) {
		_ = root.Close()
		return nil, errors.New("install directory changed while it was being opened")
	}
	return root, nil
}

func setInstallRootMetadata(root *os.Root, mode os.FileMode, uid uint64, gid uint64, preview bool) error {
	handle, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := chownInstallHandle(handle, uid, gid, preview); err != nil {
		_ = handle.Close()
		return err
	}
	if err := handle.Chmod(mode); err != nil {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}

func chownInstallHandle(handle *os.File, uid uint64, gid uint64, preview bool) error {
	if preview {
		return nil
	}
	chownUID, chownGID, err := installChownIDs(uid, gid)
	if err != nil {
		return err
	}
	return handle.Chown(chownUID, chownGID)
}

func installChownIDs(uid uint64, gid uint64) (int, int, error) {
	maxInt := uint64(^uint(0) >> 1)
	if uid > maxInt || gid > maxInt {
		return 0, 0, errors.New("unix identity exceeds the supported integer range")
	}
	return int(uid), int(gid), nil // #nosec G115 -- values are bounded to the platform int range above.
}

func openInstallRoots(plan SystemdInstallPlan) (installRoots, error) {
	config, err := openVerifiedInstallRoot(plan.ConfigDir)
	if err != nil {
		return installRoots{}, err
	}
	state, err := openVerifiedInstallRoot(plan.StateDir)
	if err != nil {
		_ = config.Close()
		return installRoots{}, err
	}
	systemd, err := openVerifiedInstallRoot(plan.SystemdDir)
	if err != nil {
		_ = config.Close()
		_ = state.Close()
		return installRoots{}, err
	}
	return installRoots{config: config, state: state, systemd: systemd}, nil
}

func (roots installRoots) close() {
	_ = roots.config.Close()
	_ = roots.state.Close()
	_ = roots.systemd.Close()
}

func writeManagedFiles(roots installRoots, plan SystemdInstallPlan, serviceUID uint64, serviceGID uint64) error {
	for _, environment := range []bool{false, true} {
		for _, file := range plan.Files {
			isEnvironment := filepath.Clean(managedFilePath(plan, file)) == filepath.Clean(plan.Unit.EnvironmentFile)
			if isEnvironment != environment {
				continue
			}
			if err := writeManagedFile(roots, plan, file, serviceUID, serviceGID); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeManagedFiles(roots installRoots, files []ManagedFileRef) error {
	for _, file := range files {
		if err := removeManagedFile(roots, file); err != nil {
			return err
		}
	}
	return nil
}

func writeManagedFile(roots installRoots, plan SystemdInstallPlan, file ManagedFile, serviceUID uint64, serviceGID uint64) error {
	rootUID, _ := installRootIDs(plan)
	root := managedFileRoot(roots, file.Area)
	uid := rootUID
	if file.Owner == ManagedFileOwnerService {
		uid = serviceUID
	}
	if err := writeAtomicInstallFile(root, file.Name, file.Data, file.Mode, uid, serviceGID, plan.AllowNonRoot); err != nil {
		return fmt.Errorf("write managed file %s/%s: %w", file.Area, file.Name, err)
	}
	return nil
}

func removeManagedFile(roots installRoots, file ManagedFileRef) error {
	root := managedFileRoot(roots, file.Area)
	info, err := root.Lstat(file.Name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect managed file %s/%s: %w", file.Area, file.Name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("remove managed file %s/%s: path is a directory", file.Area, file.Name)
	}
	if err := root.Remove(file.Name); err != nil {
		return fmt.Errorf("remove managed file %s/%s: %w", file.Area, file.Name, err)
	}
	return syncInstallRoot(root)
}

func managedFileRoot(roots installRoots, area ManagedFileArea) *os.Root {
	if area == ManagedFileState {
		return roots.state
	}
	return roots.config
}

func writeSystemdUnits(root *os.Root, plan SystemdInstallPlan) error {
	unit := plan.Unit
	if plan.AllowNonRoot {
		unit.PathValidation = PathValidationPreview
	} else {
		unit.PathValidation = PathValidationStrict
	}
	body, err := RenderSystemd(unit)
	if err != nil {
		return err
	}
	uid, gid := installRootIDs(plan)
	if err := writeAtomicInstallFile(root, plan.UnitName, []byte(body), 0o644, uid, gid, plan.AllowNonRoot); err != nil {
		return err
	}
	for _, socket := range plan.SocketUnits {
		body, renderErr := RenderSystemdSocket(socket.Unit)
		if renderErr != nil {
			return renderErr
		}
		if err := writeAtomicInstallFile(root, socket.UnitName, []byte(body), 0o644, uid, gid, plan.AllowNonRoot); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomicInstallFile(root *os.Root, name string, data []byte, mode os.FileMode, uid uint64, gid uint64, preview bool) error {
	temporary, err := installTemporaryName(name)
	if err != nil {
		return err
	}
	if err := writeInstallTemporary(root, temporary, data, mode, uid, gid, preview); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	if err := root.Rename(temporary, name); err != nil {
		_ = root.Remove(temporary)
		return err
	}
	return syncInstallRoot(root)
}

func installTemporaryName(name string) (string, error) {
	var suffix [16]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", err
	}
	return "." + name + "." + hex.EncodeToString(suffix[:]) + ".tmp", nil
}

func writeInstallTemporary(root *os.Root, name string, data []byte, mode os.FileMode, uid uint64, gid uint64, preview bool) error {
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := populateInstallTemporary(file, data, mode, uid, gid, preview); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func populateInstallTemporary(file *os.File, data []byte, mode os.FileMode, uid uint64, gid uint64, preview bool) error {
	steps := []func() error{
		func() error { _, err := file.Write(data); return err },
		func() error { return chownInstallHandle(file, uid, gid, preview) },
		func() error { return file.Chmod(mode) },
		file.Sync,
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

func syncInstallRoot(root *os.Root) error {
	handle, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}

func activateSystemdUnits(ctx context.Context, runner CommandRunner, unitNames []string) error {
	if err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	for _, unitName := range unitNames {
		if err := runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
			return fmt.Errorf("systemctl enable %s: %w", unitName, err)
		}
		if err := runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
			return fmt.Errorf("systemctl restart %s: %w", unitName, err)
		}
	}
	return nil
}
