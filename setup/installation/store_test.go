package installation

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishSuccessAndRollback(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "installations")
	store := Store{Root: root}
	value := validInstallation()
	generated := filepath.Join(t.TempDir(), "generated")
	if err := os.Mkdir(generated, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(generated, "deployment.json"), []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Publish(value, generated, func(path string) error {
		if _, err := os.Stat(filepath.Join(path, "deployment.json")); err != nil {
			t.Fatal(err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(DefaultName)
	if err != nil || loaded.Name != DefaultName {
		t.Fatalf("Load() = %+v, %v", loaded, err)
	}

	if err := os.WriteFile(filepath.Join(generated, "deployment.json"), []byte("second"), 0o600); err != nil {
		t.Fatal(err)
	}
	expected := errors.New("apply failed")
	if err := store.Publish(value, generated, func(string) error { return expected }); !errors.Is(err, expected) {
		t.Fatalf("Publish() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(root, DefaultName, "generated", "deployment.json"))
	if err != nil || string(data) != "first" {
		t.Fatalf("restored generated data = %q, %v", data, err)
	}
}
