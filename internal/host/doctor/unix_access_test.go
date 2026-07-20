package doctor

import (
	"os"
	"path/filepath"
	"testing"
)

func TestUnixAccess(t *testing.T) {
	file := UnixFile{Mode: 0o640, UID: 10, GID: 20}
	if !CanGainRead(Identity{UID: 10}, file) || !CanGainWrite(Identity{UID: 10}, file) {
		t.Fatal("owner could not control its file mode")
	}
	if !CanGainRead(Identity{UID: 11, GID: 20}, file) || CanGainWrite(Identity{UID: 11, GroupIDs: []int{20}}, file) {
		t.Fatal("group mode access was evaluated incorrectly")
	}
	if CanGainRead(Identity{UID: 11, GID: 21}, file) {
		t.Fatal("unrelated identity gained read access")
	}
	if !CanGainRead(Identity{UID: 0}, UnixFile{}) || !CanGainWrite(Identity{UID: 0}, UnixFile{}) {
		t.Fatal("root access was not recognized")
	}
}

func TestUnixDirectoryReplacement(t *testing.T) {
	open := UnixFile{Mode: os.ModeDir | 0o777, UID: 10, GID: 10}
	if !CanReplaceDirectoryEntry(Identity{UID: 20}, open) || !CanReplacePathEntry(Identity{UID: 20}, UnixFile{}, open) {
		t.Fatal("writable non-sticky directory was not replaceable")
	}
	sticky := UnixFile{Mode: os.ModeDir | os.ModeSticky | 0o777, UID: 10, GID: 10}
	if CanReplaceDirectoryEntry(Identity{UID: 20}, sticky) {
		t.Fatal("unrelated identity replaced a sticky directory entry")
	}
	if !CanReplaceDirectoryEntry(Identity{UID: 10}, sticky) || !CanReplacePathEntry(Identity{UID: 20}, UnixFile{UID: 20}, sticky) {
		t.Fatal("sticky-directory owner semantics were not preserved")
	}
	locked := UnixFile{Mode: os.ModeDir | 0o700, UID: 10, GID: 10}
	if CanReplaceDirectoryEntry(Identity{UID: 20}, locked) || CanReplacePathEntry(Identity{UID: 20}, UnixFile{}, locked) {
		t.Fatal("unwritable directory was replaceable")
	}
}

func TestInspectUnixFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if file, ok := InspectUnixFile(link, false); !ok || file.Mode&os.ModeSymlink == 0 || file.Path != link {
		t.Fatalf("lstat = %+v, %v", file, ok)
	}
	if file, ok := InspectSymlinkTarget(link); !ok || file.Path != target || !file.Mode.IsRegular() {
		t.Fatalf("target stat = %+v, %v", file, ok)
	}
	if _, ok := InspectUnixFile(filepath.Join(dir, "missing"), true); ok {
		t.Fatal("missing file was inspectable")
	}
}
