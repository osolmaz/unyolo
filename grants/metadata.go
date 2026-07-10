package grants

import (
	"fmt"
	"strings"
)

const (
	maxMetadataEntries    = 32
	maxMetadataKeyBytes   = 128
	maxMetadataValueBytes = 4096
)

func validateMetadata(metadata map[string]string) error {
	if len(metadata) > maxMetadataEntries {
		return fmt.Errorf("grant metadata exceeds %d entries", maxMetadataEntries)
	}
	for key, value := range metadata {
		if strings.TrimSpace(key) != key || key == "" || len(key) > maxMetadataKeyBytes {
			return fmt.Errorf("grant metadata key %q is invalid", key)
		}
		if strings.TrimSpace(value) == "" || len(value) > maxMetadataValueBytes {
			return fmt.Errorf("grant metadata value for %q is invalid", key)
		}
	}
	return nil
}

func stringMapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}
