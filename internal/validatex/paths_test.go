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
