//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

func waitForSystemdReady(ctx context.Context, plan SystemdInstallPlan) error {
	if plan.ReadyCheck == nil {
		if len(plan.RemoveFiles) > 0 {
			return errors.New("managed file retirement requires a readiness check")
		}
		return nil
	}
	readyContext, cancel := context.WithTimeout(ctx, durationOr(plan.ReadyTimeout, defaultReadinessTimeout))
	defer cancel()
	return pollSystemdReadiness(readyContext, plan.ReadyCheck, durationOr(plan.ReadyInterval, defaultReadinessInterval))
}

func pollSystemdReadiness(ctx context.Context, check ReadinessCheck, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return errServiceReadinessFailed
		}
		if err := check(ctx); err == nil {
			if ctx.Err() != nil {
				return errServiceReadinessFailed
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return errServiceReadinessFailed
		case <-ticker.C:
		}
	}
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
