// Package setx contains small shared set operations.
package setx

// Add inserts value and reports whether it was absent.
func Add[T comparable](values map[T]struct{}, value T) bool {
	if _, exists := values[value]; exists {
		return false
	}
	values[value] = struct{}{}
	return true
}
