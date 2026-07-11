package secretfile

import (
	"strings"
	"testing"
)

func TestParseAndRender(t *testing.T) {
	parsed, err := ParseBytes([]byte("# operators\nbob = b-secret\nalice = a-secret\n"))
	if err != nil || parsed["alice"] != "a-secret" || parsed["bob"] != "b-secret" {
		t.Fatalf("ParseBytes() = %#v, %v", parsed, err)
	}
	rendered, err := Render(parsed)
	if err != nil || string(rendered) != "alice = a-secret\nbob = b-secret\n" {
		t.Fatalf("Render() = %q, %v", rendered, err)
	}
}

func TestParseRejectsMalformedAndDuplicateRecords(t *testing.T) {
	for _, input := range []string{"", "bad name = value\n", "alice = one\nalice = two\n", "alice =\n"} {
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
