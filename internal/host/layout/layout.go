// Package layout defines the native unYOLO host release layout.
package layout

import (
	"path/filepath"
	"runtime"
	"strings"
)

const (
	linuxRoot  = "/opt/unyolo"
	darwinRoot = "/Library/Application Support/unyolo"
)

// Root returns the production bundle root for the current operating system.
func Root() string {
	if runtime.GOOS == "darwin" {
		return DarwinRoot()
	}
	return LinuxRoot()
}

// LinuxRoot returns the production bundle root used by systemd hosts.
func LinuxRoot() string { return linuxRoot }

// DarwinRoot returns the production bundle root used by launchd hosts.
func DarwinRoot() string { return darwinRoot }

// ExecutablePath returns one stable path through the active release pointer.
func ExecutablePath(destination string) string {
	return filepath.Join(Root(), "current", destination)
}

// ReleaseDestination returns the artifact destination for a path beneath one
// immutable release, or an empty string when the path is outside that layout.
func ReleaseDestination(path, root string) string {
	relative, err := filepath.Rel(filepath.Join(root, "releases"), path)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return ""
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) < 2 || parts[0] == "" {
		return ""
	}
	return filepath.Join(parts[1:]...)
}

// SafeDestination reports whether a manifest destination is a normalized
// relative path beneath a release.
func SafeDestination(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." &&
		!strings.HasPrefix(path, ".."+string(filepath.Separator))
}

// ValidCurrentTarget reports whether a current-link target selects exactly one
// immutable release directory using the host's relative link format.
func ValidCurrentTarget(target string) bool {
	if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target {
		return false
	}
	parts := strings.Split(target, string(filepath.Separator))
	return len(parts) == 2 && parts[0] == "releases" && parts[1] != "" && parts[1] != "." && parts[1] != ".."
}
