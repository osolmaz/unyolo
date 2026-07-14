//go:build !darwin

package main

import (
	"context"
	"errors"
	"io"
)

func runSetupLaunchdCommand(context.Context, io.Writer, io.Writer, io.Reader, []string) error {
	return errors.New("setup launchd is only supported on macOS")
}
