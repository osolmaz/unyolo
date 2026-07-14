package schemautil

import (
	"slices"
	"strings"
)

// SensitiveTopLevelFields returns sorted top-level fields that contain a
// write-only credential or secret value.
func SensitiveTopLevelFields(schema map[string]any) []string {
	properties, _ := schema["properties"].(map[string]any)
	result := make([]string, 0)
	for name, value := range properties {
		child, _ := value.(map[string]any)
		if IsSensitiveField(name, child) || ContainsSensitiveField(child) {
			result = append(result, name)
		}
	}
	slices.Sort(result)
	return result
}

// ContainsSensitiveField recursively checks supported JSON Schema containers.
//
//nolint:cyclop // Recursive schema composition must inspect every supported container form.
func ContainsSensitiveField(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, value := range properties {
			child, _ := value.(map[string]any)
			if IsSensitiveField(name, child) || ContainsSensitiveField(child) {
				return true
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok && ContainsSensitiveField(items) {
		return true
	}
	for _, keyword := range []string{"oneOf", "anyOf", "allOf"} {
		if branches, ok := schema[keyword].([]any); ok {
			for _, branch := range branches {
				child, _ := branch.(map[string]any)
				if ContainsSensitiveField(child) {
					return true
				}
			}
		}
	}
	return false
}

// IsSensitiveField recognizes the closed write-only field vocabulary.
func IsSensitiveField(name string, schema map[string]any) bool {
	if schema["type"] == "boolean" {
		return false
	}
	normalized := strings.ToLower(name)
	return normalized == "password" || normalized == "secret" || normalized == "token" || normalized == "private_key" ||
		normalized == "encrypted_value" || strings.HasSuffix(normalized, "_password") || strings.HasSuffix(normalized, "_secret") ||
		strings.HasSuffix(normalized, "_token") || strings.HasSuffix(normalized, "_private_key")
}
