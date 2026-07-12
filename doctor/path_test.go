package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathHelpers(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if got, ok := ResolvedCleanPath(link); !ok || got != target {
		t.Fatalf("ResolvedCleanPath() = %q, %v", got, ok)
	}
	if got := ResolvedDir(filepath.Join(link, "child")); got != target {
		t.Fatalf("ResolvedDir() = %q, want %q", got, target)
	}
	parents := ParentDirs(filepath.Join(dir, "a", "b"))
	if len(parents) < 3 || parents[0] != filepath.Join(dir, "a", "b") || parents[len(parents)-1] != string(filepath.Separator) {
		t.Fatalf("ParentDirs() = %+v", parents)
	}
	if got, ok := AbsolutePath("child", dir); !ok || got != filepath.Join(dir, "child") {
		t.Fatalf("AbsolutePath() = %q, %v", got, ok)
	}
	if got, ok := AbsolutePath(target, ""); !ok || got != target {
		t.Fatalf("absolute AbsolutePath() = %q, %v", got, ok)
	}
}
