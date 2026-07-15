package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/credentiallifecycle"
	"github.com/osolmaz/brokerkit/internal/validatex"
)

// LaunchdInstallPlan describes one complete system LaunchDaemon installation.
type LaunchdInstallPlan struct {
	User               string
	Group              string
	AdditionalGroups   []string
	GroupMembers       map[string][]string
	ConfigDir          string
	StateDir           string
	LaunchdDir         string
	PlistName          string
	Files              []ManagedFile
	RemoveFiles        []ManagedFileRef
	ReadyCheck         ReadinessCheck
	ReadyTimeout       time.Duration
	ReadyInterval      time.Duration
	Unit               LaunchdUnit
	RuntimeDirectories []LaunchdDirectory
	NoStart            bool
	AllowNonRoot       bool
	Runner             CommandRunner
	Lifecycle          *credentiallifecycle.Reporter
}

// LaunchdDirectory is one explicitly managed runtime directory required by a
// LaunchDaemon outside its config and state roots.
type LaunchdDirectory struct {
	Path  string
	Owner string
	Group string
	Mode  os.FileMode
}

// Validate validates a launchd installation without mutating the host.
func (plan LaunchdInstallPlan) Validate() error {
	validators := []func() error{
		func() error { return validateLaunchdInstallIdentity(plan) },
		func() error { return validateLaunchdInstallPaths(plan) },
		func() error { _, err := RenderLaunchd(plan.Unit); return err },
		func() error { return validateLaunchdManagedFiles(plan) },
		func() error { return validateLaunchdRuntimeDirectories(plan.RuntimeDirectories) },
		func() error { return validateLaunchdReadiness(plan) },
	}
	for _, validate := range validators {
		if err := validate(); err != nil {
			return err
		}
	}
	return nil
}

func validateLaunchdRuntimeDirectories(values []LaunchdDirectory) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !filepath.IsAbs(value.Path) || filepath.Clean(value.Path) != value.Path || value.Path == string(filepath.Separator) {
			return errors.New("launchd runtime directory must be absolute and normalized")
		}
		if _, exists := seen[value.Path]; exists {
			return fmt.Errorf("launchd runtime directory %q is duplicated", value.Path)
		}
		seen[value.Path] = struct{}{}
		if err := validatex.AccountNames(map[string]string{"runtime owner": value.Owner, "runtime group": value.Group}); err != nil {
			return err
		}
		if value.Mode == 0 || value.Mode&^os.ModePerm != 0 || value.Mode.Perm()&0o007 != 0 {
			return fmt.Errorf("launchd runtime directory %q has unsafe mode", value.Path)
		}
	}
	return nil
}

func validateLaunchdInstallIdentity(plan LaunchdInstallPlan) error {
	values, err := launchdInstallAccountNames(plan)
	if err != nil {
		return err
	}
	if err := validatex.AccountNames(values); err != nil {
		return err
	}
	if plan.Unit.UserName != plan.User || plan.Unit.GroupName != plan.Group {
		return errors.New("launchd unit identity must match the install identity")
	}
	if plan.AllowNonRoot && !plan.NoStart {
		return errors.New("non-root test installation must disable launchd bootstrap")
	}
	return nil
}

func launchdInstallAccountNames(plan LaunchdInstallPlan) (map[string]string, error) {
	values := map[string]string{"user": plan.User, "group": plan.Group}
	managed := map[string]struct{}{plan.Group: {}}
	for index, group := range plan.AdditionalGroups {
		values[fmt.Sprintf("additional group %d", index+1)] = group
		if _, exists := managed[group]; exists {
			return nil, fmt.Errorf("duplicate system group %q", group)
		}
		managed[group] = struct{}{}
	}
	for group, members := range plan.GroupMembers {
		if _, exists := managed[group]; !exists {
			return nil, fmt.Errorf("member group %q is not managed by this install plan", group)
		}
		for index, member := range members {
			values[fmt.Sprintf("%s member %d", group, index+1)] = member
		}
	}
	return values, nil
}

func validateLaunchdInstallPaths(plan LaunchdInstallPlan) error {
	if err := validatex.AbsolutePaths(map[string]string{
		"config directory": plan.ConfigDir, "state directory": plan.StateDir, "launchd directory": plan.LaunchdDir,
	}, true); err != nil {
		return err
	}
	if pathOverlaps(plan.ConfigDir, plan.StateDir) || pathOverlaps(plan.ConfigDir, plan.LaunchdDir) || pathOverlaps(plan.StateDir, plan.LaunchdDir) {
		return errors.New("launchd install roots must not overlap")
	}
	if filepath.Base(plan.PlistName) != plan.PlistName || !strings.HasSuffix(plan.PlistName, ".plist") || plan.PlistName != plan.Unit.Label+".plist" {
		return errors.New("launchd plist name must match the unit label")
	}
	return nil
}

func pathOverlaps(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	return left == right || strings.HasPrefix(left, right+string(filepath.Separator)) || strings.HasPrefix(right, left+string(filepath.Separator))
}

func validateLaunchdManagedFiles(plan LaunchdInstallPlan) error {
	if err := validateCredentialClasses(plan.Files, plan.RemoveFiles); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(plan.Files)+len(plan.RemoveFiles))
	for _, file := range plan.Files {
		if err := validateLaunchdManagedFile(plan, file); err != nil {
			return err
		}
		key := string(file.Area) + "/" + file.Name
		if _, exists := seen[key]; exists {
			return fmt.Errorf("managed file %q is duplicated", key)
		}
		seen[key] = struct{}{}
	}
	for _, file := range plan.RemoveFiles {
		key := string(file.Area) + "/" + file.Name
		if file.Area != ManagedFileConfig || !validManagedFileName(file.Name) {
			return fmt.Errorf("retired managed file %q is invalid", key)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("managed file %q is both written and removed", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validateLaunchdManagedFile(plan LaunchdInstallPlan, file ManagedFile) error {
	if !validManagedFileName(file.Name) || file.Area != ManagedFileConfig && file.Area != ManagedFileState {
		return fmt.Errorf("managed file %q is invalid", file.Name)
	}
	if err := validateManagedFilePayload(file); err != nil {
		return err
	}
	if err := validateManagedFileOwner(file); err != nil {
		return err
	}
	return validateLaunchdManagedPermissions(plan, file)
}

func validateLaunchdManagedPermissions(plan LaunchdInstallPlan, file ManagedFile) error {
	return validateManagedFileMode(file, managedFileReadable(plan.User, file))
}

func validateLaunchdReadiness(plan LaunchdInstallPlan) error {
	return validateInstallReadiness(plan.ReadyTimeout, plan.ReadyInterval, len(plan.RemoveFiles), plan.NoStart, plan.ReadyCheck)
}
