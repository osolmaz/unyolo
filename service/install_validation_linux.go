//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/osolmaz/brokerkit/internal/validatex"
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

func durationOr(value, fallback time.Duration) time.Duration {
	if value == 0 {
		return fallback
	}
	return value
}

func validateManagedFileArea(area ManagedFileArea, name string) error {
	if area != ManagedFileConfig && area != ManagedFileState {
		return fmt.Errorf("managed file %q has invalid area %q", name, area)
	}
	return nil
}

func validateManagedFilePayload(file ManagedFile) error {
	if len(file.Data) > maxManagedFileBytes {
		return fmt.Errorf("managed file %q exceeds %d bytes", file.Name, maxManagedFileBytes)
	}
	return nil
}

func validateManagedFilePermissions(plan SystemdInstallPlan, file ManagedFile) error {
	if file.Mode == 0 || file.Mode&^os.ModePerm != 0 || file.Mode.Perm()&0o022 != 0 {
		return fmt.Errorf("managed file %q has unsafe mode", file.Name)
	}
	if !managedFileReadableByService(plan, file) {
		return fmt.Errorf("managed file %q is not readable by the service", file.Name)
	}
	return nil
}

func validManagedFileName(name string) bool {
	if name == "" || name == "." || filepath.Base(name) != name || validatex.HasParentTraversal(name) {
		return false
	}
	for _, char := range name {
		if !isManagedFileNameCharacter(char) {
			return false
		}
	}
	return true
}

func isManagedFileNameCharacter(char rune) bool {
	return char != '/' && isSystemdPathCharacter(char)
}

func managedFileReadableByService(plan SystemdInstallPlan, file ManagedFile) bool {
	if file.Owner == ManagedFileOwnerService || plan.User == "root" {
		return file.Mode.Perm()&0o400 != 0
	}
	return file.Mode.Perm()&0o044 != 0
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
