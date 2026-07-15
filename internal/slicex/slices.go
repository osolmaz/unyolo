// Package slicex contains small shared slice invariants.
package slicex

// NonNil returns an empty slice for nil and otherwise preserves the input.
func NonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// Values returns the values from a map in unspecified order.
func Values[K comparable, V any](values map[K]V) []V {
	result := make([]V, 0, len(values))
	for _, value := range values {
		result = append(result, value)
	}
	return result
}

// Keys returns the keys from a map in unspecified order.
func Keys[K comparable, V any](values map[K]V) []K {
	result := make([]K, 0, len(values))
	for key := range values {
		result = append(result, key)
	}
	return result
}
