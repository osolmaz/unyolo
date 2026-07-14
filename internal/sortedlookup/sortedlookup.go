// Package sortedlookup provides lookup for immutable sorted registries.
package sortedlookup

import (
	"slices"
	"strings"
)

// String finds target in values using key. Values must already be sorted by
// the same key.
func String[T any](values []T, target string, key func(T) string) (T, bool) {
	index, found := slices.BinarySearchFunc(values, target, func(value T, target string) int {
		return strings.Compare(key(value), target)
	})
	if !found {
		var zero T
		return zero, false
	}
	return values[index], true
}

// LoadString loads one sorted registry and finds target by key.
func LoadString[T any](load func() ([]T, error), target string, key func(T) string) (T, bool) {
	values, err := load()
	if err != nil {
		var zero T
		return zero, false
	}
	return String(values, target, key)
}
