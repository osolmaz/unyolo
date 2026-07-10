package validatex

import (
	"strings"
	"testing"
)

func TestAbsolutePaths(t *testing.T) {
	if err := AbsolutePaths(map[string]string{"config": "/etc/test"}, false); err != nil {
		t.Fatal(err)
	}
	if err := AbsolutePaths(map[string]string{"config": "relative"}, false); err == nil || strings.HasPrefix(err.Error(), "--") {
		t.Fatalf("AbsolutePaths(non-flag) error = %v", err)
	}
	if err := AbsolutePaths(map[string]string{"config": "relative"}, true); err == nil || !strings.HasPrefix(err.Error(), "--config") {
		t.Fatalf("AbsolutePaths(flag) error = %v", err)
	}
}

func TestHasParentTraversal(t *testing.T) {
	for _, path := range []string{"../secret", "/safe/../secret", `safe\..\secret`} {
		if !HasParentTraversal(path) {
			t.Fatalf("HasParentTraversal(%q) = false", path)
		}
	}
	for _, path := range []string{"/safe/secret", "/safe/.../secret", "/safe/..name/secret"} {
		if HasParentTraversal(path) {
			t.Fatalf("HasParentTraversal(%q) = true", path)
		}
	}
}
