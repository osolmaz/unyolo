package setup

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
)

func TestRendererHelpers(t *testing.T) {
	if got := safeText("safe\x1b[31m\x00text"); strings.ContainsAny(got, "\x1b\x00") {
		t.Fatalf("safeText = %q", got)
	}
	lines := wrap("one two three four", 7)
	if len(lines) < 2 {
		t.Fatalf("wrap = %v", lines)
	}
	prompter := &Prompter{width: 80, height: 24}
	if _, height := prompter.selectionLayout("Choose one", flow.Navigation{}, 8); height != 0 {
		t.Fatalf("fitting menu height = %d", height)
	}
	prompter.height = 10
	description, height := prompter.selectionLayout("Choose one", flow.Navigation{}, 12)
	if height == 0 || !strings.Contains(description, "more options below") {
		t.Fatalf("clipped menu layout = %q, %d", description, height)
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
	_ = unyoloTheme(false).Theme(true)
	_ = unyoloTheme(true).Theme(false)
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
