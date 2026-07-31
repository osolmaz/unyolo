package sourceset

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDigestBindsPathsAndBytes(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "runtime"), 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "runtime", "manifest.json")
	if err := os.WriteFile(path, []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	again, err := Digest(root)
	if err != nil || again != first {
		t.Fatalf("digest is not deterministic: %q %q %v", first, again, err)
	}
	if err := os.WriteFile(path, []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	if changed == first {
		t.Fatal("digest did not bind file bytes")
	}
}

func TestDigestRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Digest(root); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
