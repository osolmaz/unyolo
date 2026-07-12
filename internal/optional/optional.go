// Package optional contains small helpers for generated optional fields.
package optional

// NonZero returns a pointer to value, or nil when value is its zero value.
func NonZero[T comparable](value T) *T {
	var zero T
	if value == zero {
		return nil
	}
	return &value
}

// Value returns the pointed-to value, or its zero value for nil.
func Value[T any](value *T) T {
	if value == nil {
		var zero T
		return zero
	}
	return *value
}
