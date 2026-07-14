//go:build !darwin

package main

import (
	"context"
	"io"
)

func runSetupLaunchdCommand(context.Context, io.Reader, io.Writer, io.Writer, []string) error {
	return exitError{code: 64, message: "setup launchd is only supported on macOS"}
}
