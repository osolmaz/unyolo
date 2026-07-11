//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

func runSetupSystemd(context.Context, []string, io.Writer, io.Writer) error {
	return errors.New("setup systemd is only supported on Linux")
}
