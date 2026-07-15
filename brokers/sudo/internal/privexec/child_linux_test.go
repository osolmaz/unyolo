//go:build linux

package privexec

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

func TestOpenTrustedPathPinsExecutableAndRejectsSymlink(t *testing.T) {
	t.Parallel()
	fd, err := openTrustedPath("/usr/bin/printf", unix.O_PATH|unix.O_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := validateExecutableDescriptor(fd); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "printf")
	if err := os.Symlink("/usr/bin/printf", link); err != nil {
		t.Fatal(err)
	}
	if linked, err := openTrustedPath(link, unix.O_PATH|unix.O_CLOEXEC); err == nil {
		_ = unix.Close(linked)
		t.Fatal("symlinked executable was opened")
	}
}

func TestTrustedExecutableAndExecveInputs(t *testing.T) {
	t.Parallel()
	fd, err := openTrustedExecutable("/usr/bin/printf")
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	if _, err := openTrustedExecutable("/"); err == nil {
		t.Fatal("directory was accepted as executable")
	}
	if groups := supplementaryGroupInts([]uint32{1, 2, 3}); len(groups) != 3 || groups[2] != 3 {
		t.Fatalf("supplementary groups = %+v", groups)
	}
	argv, environment, err := execvePointers([]string{"/usr/bin/printf", "%s"}, []string{"LANG=C"})
	if err != nil || len(argv) == 0 || environmentPointer(environment) == 0 {
		t.Fatalf("execve pointers argv=%d env=%d err=%v", len(argv), len(environment), err)
	}
	if pointer := environmentPointer(nil); pointer != 0 {
		t.Fatalf("empty environment pointer = %d", pointer)
	}
	if _, _, err := execvePointers([]string{"bad\x00argv"}, nil); err == nil {
		t.Fatal("NUL argv was accepted")
	}
	empty, argv, _, err := execveInputs([]string{"/usr/bin/printf"}, nil)
	if err != nil || empty == nil || len(argv) == 0 {
		t.Fatalf("execve inputs empty=%v argv=%d err=%v", empty, len(argv), err)
	}
	if _, _, _, err := execveInputs([]string{"bad\x00argv"}, nil); err == nil {
		t.Fatal("invalid execve inputs were accepted")
	}
	want := errors.New("stop")
	if err := firstError(func() error { return nil }, func() error { return want }); !errors.Is(err, want) {
		t.Fatalf("firstError = %v", err)
	}
	if err := errnoError(unix.EACCES); !errors.Is(err, unix.EACCES) {
		t.Fatalf("errnoError(EACCES) = %v", err)
	}
	if err := errnoError(0); err != nil {
		t.Fatalf("errnoError(0) = %v", err)
	}
}

func TestOpenChildExecHandles(t *testing.T) {
	t.Parallel()
	handles, err := openChildExecHandles(plan.Plan{WorkingDirectory: "/", Executable: "/usr/bin/printf"})
	if err != nil {
		t.Fatal(err)
	}
	handles.Close()
	if _, err := openChildExecHandles(plan.Plan{WorkingDirectory: "/", Executable: "/"}); err == nil {
		t.Fatal("invalid child exec handles were accepted")
	}
}
