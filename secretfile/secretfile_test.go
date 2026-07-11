package secretfile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndRender(t *testing.T) {
	parsed, err := ParseBytes([]byte("# operators\n123 = numeric-secret\nci@host = host-secret\nalice = a-secret\n"))
	if err != nil || parsed["alice"] != "a-secret" || parsed["123"] != "numeric-secret" || parsed["ci@host"] != "host-secret" {
		t.Fatalf("ParseBytes() = %#v, %v", parsed, err)
	}
	rendered, err := Render(parsed)
	if err != nil || string(rendered) != "123 = numeric-secret\nalice = a-secret\nci@host = host-secret\n" {
		t.Fatalf("Render() = %q, %v", rendered, err)
	}
}

func TestParseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte("alice = secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(path)
	if err != nil || parsed["alice"] != "secret" {
		t.Fatalf("Parse() = %#v, %v", parsed, err)
	}
	if _, err := Parse(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("Parse() accepted a missing file")
	}
	tooLarge := filepath.Join(t.TempDir(), "large")
	if err := os.WriteFile(tooLarge, []byte(strings.Repeat("x", maxBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(tooLarge); err == nil {
		t.Fatal("Parse() accepted an oversized file")
	}
}

func TestParseRejectsMalformedAndDuplicateRecords(t *testing.T) {
	for _, input := range []string{"", "bad name = value\n", "alice = one\nalice = two\n", "alice =\n", strings.Repeat("x", maxBytes+1)} {
		if _, err := ParseBytes([]byte(input)); err == nil {
			t.Fatalf("ParseBytes(%q) unexpectedly succeeded", input)
		}
	}
}

func TestRenderRejectsMultilineSecrets(t *testing.T) {
	if _, err := Render(map[string]string{"alice": "first\nsecond"}); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("Render() error = %v", err)
	}
}
