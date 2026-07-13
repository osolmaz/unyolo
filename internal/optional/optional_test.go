package optional

import "testing"

func TestNonZero(t *testing.T) {
	if NonZero("") != nil || NonZero(false) != nil {
		t.Fatal("NonZero() returned a pointer for a zero value")
	}
	value := NonZero("value")
	if value == nil || *value != "value" {
		t.Fatalf("NonZero(value) = %v", value)
	}
	if Value[string](nil) != "" || Value(value) != "value" {
		t.Fatal("Value() did not preserve optional semantics")
	}
}
