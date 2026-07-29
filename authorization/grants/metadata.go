package grants

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// MetadataMode stores the provider-neutral grant authorization mode.
	MetadataMode = "grant_mode"

	maxMetadataEntries    = 32
	maxMetadataKeyBytes   = 128
	maxMetadataValueBytes = 4096
)

func normalizeRequestMetadata(metadata map[string]string) map[string]string {
	normalized := make(map[string]string, len(metadata)+1)
	for key, value := range metadata {
		normalized[key] = value
	}
	if _, specified := normalized[MetadataMode]; !specified {
		normalized[MetadataMode] = "window"
	}
	return normalized
}

func validateMetadata(metadata map[string]string) error {
	if !validMetadataMode(metadata[MetadataMode]) {
		return errors.New("grant metadata mode is invalid")
	}
	if len(metadata) > maxMetadataEntries {
		return fmt.Errorf("grant metadata exceeds %d entries", maxMetadataEntries)
	}
	for key, value := range metadata {
		if err := validateMetadataEntry(key, value); err != nil {
			return err
		}
	}
	return nil
}

func validateMetadataEntry(key, value string) error {
	if strings.TrimSpace(key) != key || key == "" || len(key) > maxMetadataKeyBytes {
		return fmt.Errorf("grant metadata key %q is invalid", key)
	}
	if strings.TrimSpace(value) == "" || len(value) > maxMetadataValueBytes {
		return fmt.Errorf("grant metadata value for %q is invalid", key)
	}
	return nil
}

func validMetadataMode(mode string) bool {
	return mode == "window" || mode == "execution"
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
