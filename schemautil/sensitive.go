package schemautil

import (
	"slices"
	"strings"
)

var exactSensitiveFields = []string{"encrypted_value", "password", "private_key", "secret", "token"}
var sensitiveSuffixes = []string{"_password", "_private_key", "_secret", "_token"}

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
func ContainsSensitiveField(schema map[string]any) bool {
	if schema == nil {
		return false
	}
	return containsSensitiveProperty(schema) || containsSensitiveItems(schema) || containsSensitiveBranch(schema)
}

func containsSensitiveProperty(schema map[string]any) bool {
	if properties, ok := schema["properties"].(map[string]any); ok {
		for name, value := range properties {
			child, _ := value.(map[string]any)
			if IsSensitiveField(name, child) || ContainsSensitiveField(child) {
				return true
			}
		}
	}
	return false
}

func containsSensitiveItems(schema map[string]any) bool {
	if items, ok := schema["items"].(map[string]any); ok && ContainsSensitiveField(items) {
		return true
	}
	return false
}

func containsSensitiveBranch(schema map[string]any) bool {
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
	if slices.Contains(exactSensitiveFields, normalized) {
		return true
	}
	return slices.ContainsFunc(sensitiveSuffixes, func(suffix string) bool { return strings.HasSuffix(normalized, suffix) })
}
