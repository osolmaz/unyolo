// Package copyx contains small internal copy helpers.
package copyx

import "slices"

// StringMap returns a shallow copy of values.
func StringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

// StringSliceMap returns a deep copy of string slice values.
func StringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, value := range values {
		out[key] = slices.Clone(value)
	}
	return out
}
