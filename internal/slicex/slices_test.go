package slicex

import "testing"

func TestNonNil(t *testing.T) {
	if value := NonNil[int](nil); value == nil || len(value) != 0 {
		t.Fatalf("nil result = %#v", value)
	}
	input := []int{1}
	if value := NonNil(input); len(value) != 1 || value[0] != 1 {
		t.Fatalf("preserved result = %#v", value)
	}
}
