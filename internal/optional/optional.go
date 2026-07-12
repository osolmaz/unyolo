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
