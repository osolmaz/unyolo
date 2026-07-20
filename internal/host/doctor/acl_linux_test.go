//go:build linux

package doctor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLinuxPathACLState(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "secret")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := pathACLState(path); got != aclAbsent {
		t.Fatalf("plain path ACL state = %v", got)
	}
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is unavailable")
	}
	if output, runErr := exec.CommandContext(context.Background(), setfacl, "-m", "u:nobody:r", path).CombinedOutput(); runErr != nil { // #nosec G204 -- test executes a fixed system utility and fixture path.
		t.Skipf("could not create ACL fixture: %v: %s", runErr, output)
	}
	if got := pathACLState(path); got != aclPresent {
		t.Fatalf("extended path ACL state = %v", got)
	}
	checks := SecretFileChecks(path, Identity{User: "nobody", UID: 65534, GID: 65534})
	if checks[0].Status != CheckUnknown {
		t.Fatalf("ACL secret path check = %+v", checks[0])
	}
}

func TestWritableParentTakesPrecedenceOverACLUncertainty(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o777); err != nil { // #nosec G302 -- world-writable directory is the isolation failure fixture.
		t.Fatal(err)
	}
	path := filepath.Join(directory, "secret")
	if err := os.WriteFile(path, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	setfacl, err := exec.LookPath("setfacl")
	if err != nil {
		t.Skip("setfacl is unavailable")
	}
	if output, runErr := exec.CommandContext(context.Background(), setfacl, "-m", "u:nobody:---", path).CombinedOutput(); runErr != nil { // #nosec G204 -- test executes a fixed system utility and fixture path.
		t.Skipf("could not create ACL fixture: %v: %s", runErr, output)
	}
	checks := SecretFileChecks(path, Identity{User: "nobody", UID: 65534, GID: 65534})
	if checks[0].Status != CheckFail {
		t.Fatalf("replaceable ACL path check = %+v", checks[0])
	}
}

func TestMergeACLStates(t *testing.T) {
	for _, test := range []struct {
		left  aclState
		right aclState
		want  aclState
	}{
		{left: aclAbsent, right: aclAbsent, want: aclAbsent},
		{left: aclUnknown, right: aclAbsent, want: aclUnknown},
		{left: aclAbsent, right: aclPresent, want: aclPresent},
	} {
		if got := mergeACLStates(test.left, test.right); got != test.want {
			t.Fatalf("mergeACLStates(%v, %v) = %v, want %v", test.left, test.right, got, test.want)
		}
	}
}

func TestXattrACLErrorState(t *testing.T) {
	for _, err := range []error{syscall.ENOTSUP, syscall.EOPNOTSUPP, syscall.ENODATA} {
		if got := xattrACLErrorState(err); got != aclAbsent {
			t.Fatalf("xattrACLErrorState(%v) = %v, want absent", err, got)
		}
	}
	if got := xattrACLErrorState(errors.New("unknown")); got != aclUnknown {
		t.Fatalf("xattrACLErrorState(unknown) = %v, want unknown", got)
	}
}
