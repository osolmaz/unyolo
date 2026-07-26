// Package pathutil provides shared lexical path checks.
package pathutil

import (
	"path/filepath"
	"strings"
)

// Overlap reports whether either clean path contains the other.
func Overlap(first, second string) bool {
	first, second = filepath.Clean(first), filepath.Clean(second)
	separator := string(filepath.Separator)
	return first == second || strings.HasPrefix(first, second+separator) || strings.HasPrefix(second, first+separator)
}
