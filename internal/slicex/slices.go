// Package slicex contains small shared slice invariants.
package slicex

// NonNil returns an empty slice for nil and otherwise preserves the input.
func NonNil[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}
