//go:build !linux

package service

import (
	"context"
	"errors"
)

// InstallSystemd rejects systemd installation on unsupported hosts.
func InstallSystemd(context.Context, SystemdInstallPlan) error {
	return errors.New("systemd installation is only supported on Linux")
}
