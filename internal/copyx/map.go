// Package copyx contains small internal copy helpers.
package copyx

import (
	"slices"
	"sort"
)

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

// CanonicalStringSlice returns a sorted copy with duplicate values removed.
func CanonicalStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := slices.Clone(values)
	sort.Strings(out)
	return slices.Compact(out)
}

// CanonicalStringSliceMap returns a deep canonical copy of string slice values.
func CanonicalStringSliceMap(values map[string][]string) map[string][]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string][]string, len(values))
	for key, value := range values {
		out[key] = CanonicalStringSlice(value)
	}
	return out
}

// StringSliceMapsEqual compares map values as unordered sets.
func StringSliceMapsEqual(left, right map[string][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, leftValues := range left {
		rightValues, ok := right[key]
		if !ok || !StringSlicesEqual(leftValues, rightValues) {
			return false
		}
	}
	return true
}

// StringSlicesEqual compares slice values as unordered sets.
func StringSlicesEqual(left, right []string) bool {
	return slices.Equal(CanonicalStringSlice(left), CanonicalStringSlice(right))
}
