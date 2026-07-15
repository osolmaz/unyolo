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

func TestValues(t *testing.T) {
	values := Values(map[string]int{"one": 1, "two": 2})
	if len(values) != 2 || values[0]+values[1] != 3 {
		t.Fatalf("Values() = %#v", values)
	}
}

func TestKeys(t *testing.T) {
	keys := Keys(map[string]int{"one": 1, "two": 2})
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("Keys() = %#v", keys)
	}
}
