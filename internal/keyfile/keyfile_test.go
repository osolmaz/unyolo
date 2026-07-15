package keyfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreate(t *testing.T) {
	for _, encoding := range []Encoding{Raw, Base64} {
		t.Run(string(rune('0'+encoding)), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key")
			created, err := LoadOrCreate(path, 32, "test", encoding)
			if err != nil || len(created) != 32 {
				t.Fatalf("create = %d bytes, %v", len(created), err)
			}
			loaded, err := LoadOrCreate(path, 32, "test", encoding)
			if err != nil || string(loaded) != string(created) {
				t.Fatalf("load = %d bytes, %v", len(loaded), err)
			}
			existing, err := LoadExisting(path, 32, "test", encoding)
			if err != nil || string(existing) != string(created) {
				t.Fatalf("existing = %d bytes, %v", len(existing), err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrCreate(path, 32, "test", encoding); err == nil {
				t.Fatal("unsafe permissions accepted")
			}
		})
	}
	if _, err := LoadExisting(filepath.Join(t.TempDir(), "missing"), 32, "test", Raw); err == nil {
		t.Fatal("LoadExisting created a missing key")
	}
}
