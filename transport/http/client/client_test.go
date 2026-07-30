package clienthttp

import (
	"net/http"
	"testing"
)

func TestParseBaseURLAndSecureClient(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"", "ftp://example.test", "http://user@example.test", "http://example.test?q=1",
		"https://example.test?", "https://example.test#",
	} {
		if _, err := ParseBaseURL(value); err == nil {
			t.Fatalf("ParseBaseURL(%q) succeeded", value)
		}
	}
	if parsed, err := ParseBaseURL("https://example.test/base"); err != nil || parsed.Path != "/base" {
		t.Fatalf("ParseBaseURL() = %v, %v", parsed, err)
	}
	provided := &http.Client{}
	secure := Secure(provided)
	if secure == provided || secure.CheckRedirect == nil || provided.CheckRedirect != nil {
		t.Fatal("Secure() did not clone and harden the client")
	}
	if defaultClient := Secure(nil); defaultClient.Timeout == 0 || defaultClient.CheckRedirect == nil {
		t.Fatal("Secure(nil) omitted safety defaults")
	}
}
