// Package slicex contains small shared slice invariants.
package slicex

import (
	"maps"
	"slices"
)

// NonNil returns an empty slice for nil and otherwise preserves the input.
func NonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

// Values returns the values from a map in unspecified order.
func Values[K comparable, V any](values map[K]V) []V {
	return slices.Collect(maps.Values(values))
}

// Keys returns the keys from a map in unspecified order.
func Keys[K comparable, V any](values map[K]V) []K {
	return slices.Collect(maps.Keys(values))
}
