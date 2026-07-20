package endpoint

import "testing"

func TestValidateHTTPOrigin(t *testing.T) {
	for _, raw := range []string{"https://api.github.com/", "https://github.example/api/v3/", "http://127.0.0.1:9000/", "http://[::1]:9000/"} {
		development := raw[:5] == "http:"
		if err := ValidateHTTPOrigin(raw, development); err != nil {
			t.Fatalf("ValidateHTTPOrigin(%q, %t): %v", raw, development, err)
		}
	}
	for _, test := range []struct {
		raw         string
		development bool
	}{
		{"http://127.0.0.1:9000/", false},
		{"http://localhost:9000/", true},
		{"http://192.0.2.1:9000/", true},
		{"https://user@example.test/", false},
		{"https://example.test/?token=x", false},
		{"https://example.test/a/../b", false},
		{"ftp://example.test/", false},
	} {
		if err := ValidateHTTPOrigin(test.raw, test.development); err == nil {
			t.Fatalf("ValidateHTTPOrigin(%q, %t) error = nil", test.raw, test.development)
		}
	}
}
