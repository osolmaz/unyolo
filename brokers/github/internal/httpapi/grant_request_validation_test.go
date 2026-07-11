package httpapi

import (
	"strings"
	"testing"
)

func TestValidateClientRequestID(t *testing.T) {
	for _, value := range []string{"", " ", " leading", "trailing ", "two words", strings.Repeat("a", 129)} {
		if err := validateClientRequestID(value); err == nil {
			t.Fatalf("validateClientRequestID(%q) succeeded", value)
		}
	}
	for _, value := range []string{"request-1", strings.Repeat("a", 128)} {
		if err := validateClientRequestID(value); err != nil {
			t.Fatalf("validateClientRequestID(%q) error = %v", value, err)
		}
	}
}
