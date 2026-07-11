//go:build linux

package hostcheck

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidatePathACLClassification(t *testing.T) {
	t.Parallel()
	getter := func(_ string, name string, _ []byte) (int, error) {
		if name == "system.posix_acl_access" {
			return 0, unix.ENODATA
		}
		return 0, nil
	}
	if err := validatePathACLWith("/test", true, getter); err != nil {
		t.Fatal(err)
	}
	if err := validatePathACLWith("/test", false, func(string, string, []byte) (int, error) { return 8, nil }); err == nil {
		t.Fatal("extended ACL was accepted")
	}
	want := errors.New("inspect failed")
	if err := validatePathACLWith("/test", false, func(string, string, []byte) (int, error) { return 0, want }); !errors.Is(err, want) {
		t.Fatalf("ACL inspection error = %v", err)
	}
}
