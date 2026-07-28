// Package validatex contains small validation helpers shared inside unyolo.
package validatex

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AbsolutePaths validates a named set of absolute filesystem paths.
func AbsolutePaths(values map[string]string, flagStyle bool) error {
	for name, value := range values {
		if !filepath.IsAbs(value) {
			if flagStyle {
				return fmt.Errorf("--%s must be absolute", name)
			}
			return fmt.Errorf("%s must be absolute", name)
		}
	}
	return nil
}

// HasParentTraversal reports whether path contains an uncleaned `..` component.
func HasParentTraversal(path string) bool {
	for _, component := range strings.FieldsFunc(path, func(char rune) bool {
		return char == '/' || char == '\\'
	}) {
		if component == ".." {
			return true
		}
	}
	return false
}
