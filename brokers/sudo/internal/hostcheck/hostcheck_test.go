//go:build linux || darwin

package hostcheck

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/plan"
)

func TestValidateExecutionAcceptsTrustedSystemPaths(t *testing.T) {
	t.Parallel()
	if err := ValidateExecution(plan.Plan{Executable: "/usr/bin/printf", WorkingDirectory: "/", TargetUID: 0}, uint32(os.Getuid())); err != nil { // #nosec G115 -- uid is non-negative.
		t.Fatal(err)
	}
	if err := ValidateRootFile("/usr/bin/true"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateRootDirectory("/"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStaleSocket("/definitely-missing-sudo-broker-test.sock", uint32(os.Getuid())); err != nil { // #nosec G115 -- uid is non-negative.
		t.Fatal(err)
	}
	strong, err := KernelExecutionSafety()
	if err != nil || strong != (runtime.GOOS == "linux") {
		t.Fatalf("kernel safety = %t, %v", strong, err)
	}
	if err := validatePathACL("/usr/bin/true", false); err != nil {
		t.Fatal(err)
	}
	if err := validatePathACL("/definitely-missing-sudo-broker-acl", false); runtime.GOOS == "linux" && err == nil {
		t.Fatal("missing ACL path was accepted")
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
	if err := ValidateRootFile("/"); err == nil {
		t.Fatal("directory was accepted as root file")
	}
	if err := ValidateStaleSocket(executable, uint32(os.Getuid())); err == nil { // #nosec G115 -- uid is non-negative.
		t.Fatal("regular file was accepted as stale socket")
	}
}

func TestValidateStaleSocketInfoAcceptsOnlyOwnedSockets(t *testing.T) {
	t.Parallel()
	socketPath := filepath.Join(t.TempDir(), "helper.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	info, err := os.Lstat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStaleSocketInfo(info, uint32(os.Getuid())); err != nil { // #nosec G115 -- uid is non-negative.
		t.Fatal(err)
	}
	if os.Getuid() != 0 {
		if err := validateStaleSocketInfo(info, uint32(os.Getuid()+1)); err == nil { // #nosec G115 -- uid is non-negative in tests.
			t.Fatal("socket owned by another unprivileged uid was accepted")
		}
	}
	regularPath := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(regularPath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	regularInfo, err := os.Lstat(regularPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateStaleSocketInfo(regularInfo, uint32(os.Getuid())); err == nil { // #nosec G115 -- uid is non-negative.
		t.Fatal("regular file was accepted as a stale socket")
	}
}
