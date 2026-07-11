//go:build linux || darwin

package hostcheck

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
)

func TestValidateExecutionAcceptsTrustedSystemPaths(t *testing.T) {
	t.Parallel()
	if err := ValidateExecution(plan.Plan{Executable: "/usr/bin/printf", WorkingDirectory: "/", TargetUID: 0}, uint32(os.Getuid())); err != nil { // #nosec G115 -- uid is non-negative.
		t.Fatal(err)
	}
}

func TestValidateExecutionRejectsWritableAndSymlinkedPaths(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	executable := filepath.Join(directory, "tool")
	if err := os.WriteFile(executable, []byte("tool"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ValidateExecution(plan.Plan{Executable: executable, WorkingDirectory: "/", TargetUID: uint32(os.Getuid())}, uint32(os.Getuid())); err == nil { // #nosec G115 -- uid is non-negative.
		t.Fatal("user-owned executable was accepted")
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink("/usr/bin/printf", link); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRootFile(link); err == nil {
		t.Fatal("symlinked file was accepted")
	}
}
