package bundle

import (
	"context"
	"path/filepath"
	"strconv"
	"strings"
)

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runCommand(ctx, name, args...)
}

// NewNativeManager returns the supported native system service adapter.
func NewNativeManager() ServiceManager { return newNativeManager(execRunner{}) }

// launchdPlistPath returns the root-owned system LaunchDaemon path for a
// bounded service label.
func launchdPlistPath(service string) string {
	return filepath.Join("/Library/LaunchDaemons", service+".plist")
}

// launchdSystemTarget returns the domain-qualified launchd label used with
// bootstrap, bootout, and printer subcommands.
func launchdSystemTarget(service string) string { return "system/" + service }

// launchdParsePID extracts the reported PID from `launchctl print` output.
// Returns zero when no explicit process identifier is available.
func launchdParsePID(output string) int {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "pid" {
			pid, err := strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return 0
			}
			return pid
		}
	}
	return 0
}
