package validatex

import (
	"fmt"
	"regexp"
)

var accountNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// AccountNames validates literal Unix account names without service-manager
// expansion syntax.
func AccountNames(values map[string]string) error {
	for name, value := range values {
		if !accountNamePattern.MatchString(value) {
			return fmt.Errorf("%s %q is invalid", name, value)
		}
	}
	return nil
}
