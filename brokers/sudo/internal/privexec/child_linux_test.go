//go:build linux

package privexec

import (
	"os"
	"path/filepath"
	"testing"

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
