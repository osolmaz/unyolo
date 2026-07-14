//go:build !linux && !darwin

package main

import (
	"context"
	"io"
)

func runSetupSystemd(ctx context.Context, stdout io.Writer, opts setupSystemdOptions) error {
	return exitError{code: 64, message: "setup systemd is only supported on Linux"}
}
