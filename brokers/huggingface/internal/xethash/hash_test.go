package xethash

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	t.Parallel()
	for name, value := range map[string]string{
		"short":     "abc",
		"uppercase": strings.Repeat("A", 64),
		"non hex":   strings.Repeat("g", 64),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if Valid(value) {
				t.Fatalf("Valid(%q) = true", value)
			}
		})
	}
	if !Valid(strings.Repeat("a", 64)) {
		t.Fatal("Valid() rejected a lowercase 64-character hash")
	}
}
