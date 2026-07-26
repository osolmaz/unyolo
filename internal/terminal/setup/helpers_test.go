package setup

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/flow"
)

func TestRendererHelpers(t *testing.T) {
	if got := safeText("safe\x1b[31m\x00text"); strings.ContainsAny(got, "\x1b\x00") {
		t.Fatalf("safeText = %q", got)
	}
	lines := wrap("one two three four", 7)
	if len(lines) < 2 {
		t.Fatalf("wrap = %v", lines)
	}
	for _, test := range []struct{ count, want int }{{0, 3}, {2, 3}, {10, 10}} {
		if got := selectHeight(test.count); got != test.want {
			t.Fatalf("selectHeight(%d) = %d", test.count, got)
		}
	}
	validator := promptValidator(flow.Prompt{Required: true, Validate: func(value string) error {
		if len(value) < 2 || len(value) > 4 || strings.Trim(value, "abcdefghijklmnopqrstuvwxyz") != "" {
			return os.ErrInvalid
		}
		return nil
	}})
	if err := validator("abc"); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"", "a", "abcde", "12"} {
		if err := validator(value); err == nil {
			t.Fatalf("value %q was accepted", value)
		}
	}
	_ = brokerKitTheme(false).Theme(true)
	_ = brokerKitTheme(true).Theme(false)
}

func TestColorAndWidthEnvironment(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	t.Setenv("NO_COLOR", "1")
	if colorEnabled(file) {
		t.Fatal("NO_COLOR was ignored")
	}
	t.Setenv("NO_COLOR", "")
	t.Setenv("FORCE_COLOR", "1")
	if !colorEnabled(file) {
		t.Fatal("FORCE_COLOR was ignored")
	}
	if width := terminalWidth(&bytes.Buffer{}); width < 20 {
		t.Fatalf("terminal width = %d", width)
	}
}
