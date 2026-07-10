// Package validatex contains small validation helpers shared inside brokerkit.
package validatex

import (
	"fmt"
	"path/filepath"
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
