//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func runSetupSystemd(context.Context, io.Writer, setupSystemdOptions) error {
	return errors.New("setup systemd is only supported on Linux")
}
