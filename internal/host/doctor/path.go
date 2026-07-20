package doctor

import "path/filepath"

// ParentDirs returns an absolute path followed by each parent through the root.
func ParentDirs(path string) []string {
	cleaned := CleanPath(path)
	var dirs []string
	for {
		dirs = append(dirs, cleaned)
		parent := filepath.Dir(cleaned)
		if parent == cleaned {
			return dirs
		}
		cleaned = parent
	}
}

// CleanPath returns an absolute clean path when the working directory is available.
func CleanPath(path string) string {
	if absolute, err := filepath.Abs(path); err == nil {
		return absolute
	}
	return filepath.Clean(path)
}

// ResolvedDir resolves symlinks in a path's parent directory when possible.
func ResolvedDir(path string) string {
	directory := filepath.Dir(CleanPath(path))
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return directory
	}
	return resolved
}

// ResolvedCleanPath resolves all symlinks in a clean absolute path.
func ResolvedCleanPath(path string) (string, bool) {
	resolved, err := filepath.EvalSymlinks(CleanPath(path))
	return resolved, err == nil
}

// AbsolutePath resolves path against baseDir, or the process working directory.
func AbsolutePath(path, baseDir string) (string, bool) {
	if filepath.IsAbs(path) {
		return filepath.Clean(path), true
	}
	if baseDir != "" {
		return filepath.Clean(filepath.Join(baseDir, path)), true
	}
	absolute, err := filepath.Abs(path)
	return absolute, err == nil
}
