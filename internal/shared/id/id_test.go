package id

import "testing"

func TestNewReturnsPrefixedUniqueID(t *testing.T) {
	t.Parallel()
	first, err := New("evt")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	second, err := New("evt")
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if first == second {
		t.Fatalf("New() returned duplicate ids: %q", first)
	}
	if len(first) <= len("evt_") || first[:4] != "evt_" {
		t.Fatalf("New() = %q, want evt_ prefix", first)
	}
}
