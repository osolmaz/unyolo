// Package coverage runs a consistent Go coverage gate for broker repositories.
package coverage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Run executes `go test` and enforces minimum total statement coverage.
func Run(ctx context.Context, directory string, minimum float64) (float64, error) {
	if minimum < 0 || minimum > 100 {
		return 0, errors.New("minimum coverage must be between 0 and 100")
	}
	profile, err := os.CreateTemp("", "brokerkit-cover-*.out")
	if err != nil {
		return 0, err
	}
	path := profile.Name()
	_ = profile.Close()
	defer func() { _ = os.Remove(path) }()
	if err := goCommand(ctx, directory, "test", "./...", "-coverprofile="+path); err != nil {
		return 0, err
	}
	// #nosec G204 -- path is a private temporary file created above.
	cover := exec.CommandContext(ctx, "go", "tool", "cover", "-func="+filepath.Clean(path))
	cover.Dir = directory
	output, err := cover.Output()
	if err != nil {
		return 0, fmt.Errorf("summarize coverage: %w", err)
	}
	return enforceMinimum(output, minimum)
}

func enforceMinimum(output []byte, minimum float64) (float64, error) {
	total, err := parseTotal(output)
	if err != nil {
		return 0, err
	}
	if total < minimum {
		return total, fmt.Errorf("total coverage %.1f%% is below %.1f%%", total, minimum)
	}
	return total, nil
}

func goCommand(ctx context.Context, directory string, args ...string) error {
	// #nosec G204 -- the executable is fixed and callers provide Go tool arguments only.
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = directory
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

func parseTotal(output []byte) (float64, error) {
	for _, line := range bytes.Split(output, []byte("\n")) {
		fields := bytes.Fields(line)
		if len(fields) == 3 && string(fields[0]) == "total:" {
			return strconv.ParseFloat(strings.TrimSuffix(string(fields[2]), "%"), 64)
		}
	}
	return 0, errors.New("go coverage output did not contain a total")
}
