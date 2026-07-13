package schemautil

// RemoveRequiredProperty removes name from a decoded JSON Schema required list.
func RemoveRequiredProperty(schema map[string]any, name string) {
	values, ok := schema["required"].([]any)
	if !ok {
		return
	}
	filtered := values[:0]
	for _, value := range values {
		if value != name {
			filtered = append(filtered, value)
		}
	}
	if len(filtered) == 0 {
		delete(schema, "required")
		return
	}
	schema["required"] = filtered
}
