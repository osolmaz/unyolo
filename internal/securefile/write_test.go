package securefile //nolint:testpackage // Tests exercise private failure paths.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndSync(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "value")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteAndSync(file, []byte("value"), "test value"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "value" {
		t.Fatalf("stored value = %q, %v", data, err)
	}
	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := WriteAndSync(closed, []byte("value"), "test value"); err == nil {
		t.Fatal("WriteAndSync accepted a closed file")
	}
}
