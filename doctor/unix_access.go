package doctor

import (
	"os"
	"path/filepath"
	"slices"
)

// UnixFile describes the ownership and mode facts used by isolation checks.
type UnixFile struct {
	Path string
	Mode os.FileMode
	UID  int
	GID  int
}

// InspectUnixFile inspects a path without reading its contents.
func InspectUnixFile(path string, followSymlink bool) (UnixFile, bool) {
	info, err := lstatOrStat(path, followSymlink)
	if err != nil {
		return UnixFile{}, false
	}
	uid, gid, ok := unixOwnership(info)
	if !ok {
		return UnixFile{}, false
	}
	return UnixFile{Path: path, Mode: info.Mode(), UID: uid, GID: gid}, true
}

// InspectSymlinkTarget resolves path and inspects the resulting file.
func InspectSymlinkTarget(path string) (UnixFile, bool) {
	target, err := filepath.EvalSymlinks(CleanPath(path))
	if err != nil {
		return UnixFile{}, false
	}
	return InspectUnixFile(target, true)
}

func lstatOrStat(path string, followSymlink bool) (os.FileInfo, error) {
	if followSymlink {
		return os.Stat(path)
	}
	return os.Lstat(path)
}

// CanGainRead reports whether identity can read a file now or can grant itself
// read access as the owner.
func CanGainRead(identity Identity, file UnixFile) bool {
	return canGainAccess(identity, file, 0o400, 0o040, 0o004)
}

// CanGainWrite reports whether identity can write a file now or can grant
// itself write access as the owner.
func CanGainWrite(identity Identity, file UnixFile) bool {
	return canGainAccess(identity, file, 0o200, 0o020, 0o002)
}

// CanReplaceDirectoryEntry reports whether identity can create, remove, or
// rename entries in a directory under Unix mode and sticky-bit semantics.
func CanReplaceDirectoryEntry(identity Identity, directory UnixFile) bool {
	if !CanGainWrite(identity, directory) {
		return false
	}
	if directory.Mode&os.ModeDir == 0 || directory.Mode&os.ModeSticky == 0 {
		return true
	}
	return identity.UID == 0 || identity.UID == directory.UID
}

// CanReplacePathEntry reports whether identity can replace entry in parent
// under Unix mode and sticky-bit semantics.
func CanReplacePathEntry(identity Identity, entry, parent UnixFile) bool {
	if !CanGainWrite(identity, parent) {
		return false
	}
	if parent.Mode&os.ModeDir == 0 || parent.Mode&os.ModeSticky == 0 {
		return true
	}
	return identity.UID == 0 || identity.UID == parent.UID || identity.UID == entry.UID
}

func canGainAccess(identity Identity, file UnixFile, owner, group, other os.FileMode) bool {
	if identity.UID == 0 || identity.UID == file.UID {
		return true
	}
	permissions := file.Mode.Perm()
	if identity.GID == file.GID || slices.Contains(identity.GroupIDs, file.GID) {
		return permissions&group != 0
	}
	return permissions&other != 0
}
