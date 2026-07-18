//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
)

func waitForSystemdReady(ctx context.Context, plan SystemdInstallPlan) error {
	if plan.ReadyCheck == nil {
		if len(plan.RemoveFiles) > 0 {
			return errors.New("managed file retirement requires a readiness check")
		}
		return nil
	}
	return waitForReadiness(ctx, plan.ReadyCheck, plan.ReadyTimeout, plan.ReadyInterval)
}

func validateManagedFileArea(area ManagedFileArea, name string) error {
	if area != ManagedFileConfig && area != ManagedFileState {
		return fmt.Errorf("managed file %q has invalid area %q", name, area)
	}
	return nil
}

func validateManagedFilePermissions(plan SystemdInstallPlan, file ManagedFile) error {
	return validateManagedFileMode(file, managedFileReadable(plan.User, file))
}

func managedFilePath(plan SystemdInstallPlan, file ManagedFile) string {
	return managedFileRefPath(plan, ManagedFileRef{Area: file.Area, Name: file.Name})
}

func managedFileRefPath(plan SystemdInstallPlan, file ManagedFileRef) string {
	if file.Area == ManagedFileState {
		return filepath.Join(plan.StateDir, file.Name)
	}
	return filepath.Join(plan.ConfigDir, file.Name)
}

func managedFileKey(area ManagedFileArea, name string) string {
	return string(area) + "/" + name
}
