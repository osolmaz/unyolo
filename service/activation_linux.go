//go:build linux

package service

import (
	"context"
	"fmt"
	"strings"
)

func activateSystemdUnits(ctx context.Context, runner CommandRunner, serviceUnit string, unitNames []string) error {
	if err := runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w", err)
	}
	for _, unitName := range unitNames {
		if err := runner.Run(ctx, "systemctl", "enable", unitName); err != nil {
			return fmt.Errorf("systemctl enable %s: %w", unitName, err)
		}
	}
	if containsSystemdSocket(unitNames) {
		if err := stopSocketActivatedService(ctx, runner, serviceUnit, unitNames); err != nil {
			return err
		}
	}
	return restartSystemdUnits(ctx, runner, unitNames)
}

func stopSocketActivatedService(ctx context.Context, runner CommandRunner, serviceUnit string, unitNames []string) error {
	args := []string{"stop", serviceUnit}
	for _, unitName := range unitNames {
		if strings.HasSuffix(unitName, ".socket") {
			args = append(args, unitName)
		}
	}
	if err := runner.Run(ctx, "systemctl", args...); err != nil {
		return fmt.Errorf("stop socket-activated service %s: %w", serviceUnit, err)
	}
	return nil
}

func containsSystemdSocket(unitNames []string) bool {
	for _, unitName := range unitNames {
		if strings.HasSuffix(unitName, ".socket") {
			return true
		}
	}
	return false
}

func restartSystemdUnits(ctx context.Context, runner CommandRunner, unitNames []string) error {
	for _, sockets := range []bool{true, false} {
		for _, unitName := range unitNames {
			if strings.HasSuffix(unitName, ".socket") != sockets {
				continue
			}
			if err := runner.Run(ctx, "systemctl", "restart", unitName); err != nil {
				return fmt.Errorf("systemctl restart %s: %w", unitName, err)
			}
		}
	}
	return nil
}
