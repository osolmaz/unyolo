package setup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/flow"
)

func TestAccessiblePromptSurface(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	options := []flow.Option{{Value: "one", Label: "One"}, {Value: "two", Label: "Two", Hint: "second"}}
	tests := []struct {
		name  string
		input string
		run   func(*Prompter) error
	}{
		{"select", "1\n", func(prompter *Prompter) error {
			value, err := prompter.Select(context.Background(), flow.SelectPrompt{Message: "Choose", Options: options, InitialValue: "one"})
			if err == nil && value == "" {
				t.Fatal("select returned no value")
			}
			return err
		}},
		{"multiselect", "0\n", func(prompter *Prompter) error {
			values, err := prompter.MultiSelect(context.Background(), flow.SelectPrompt{Message: "Choose many", Options: options, InitialValues: []string{"one"}, Required: true})
			if err == nil && len(values) == 0 {
				t.Fatal("multiselect returned no values")
			}
			return err
		}},
		{"text", "value\n", func(prompter *Prompter) error {
			value, err := prompter.Text(context.Background(), flow.Prompt{Message: "Name", Required: true})
			if err == nil && value != "value" {
				t.Fatalf("text = %q", value)
			}
			return err
		}},
		{"confirm", "y\n", func(prompter *Prompter) error {
			_, err := prompter.Confirm(context.Background(), flow.ConfirmPrompt{Message: "Continue?"})
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			prompter := New(Options{Input: strings.NewReader(test.input), Output: &output, Accessible: true, Width: 60})
			if err := test.run(prompter); err != nil {
				t.Fatal(err)
			}
			if err := prompter.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAccessibleEOFCancelsPrompt(t *testing.T) {
	var output bytes.Buffer
	prompter := New(Options{Input: strings.NewReader(""), Output: &output, Accessible: true, Width: 60})
	_, err := prompter.MultiSelect(context.Background(), flow.SelectPrompt{
		Message: "Choose", Required: true, InitialValues: []string{"one"},
		Options: []flow.Option{{Value: "one", Label: "One"}},
	})
	var cancelled flow.CancelledError
	if !errors.As(err, &cancelled) || !errors.Is(err, io.EOF) {
		t.Fatalf("EOF = %v", err)
	}
}

func TestAccessibleNotesLinksAndProgressFailure(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	opened := false
	prompter := New(Options{
		Output: &output, Accessible: true, Width: 40,
		OpenURL: func(context.Context, string) error { opened = true; return nil },
	})
	if err := prompter.Intro(context.Background(), "Setup"); err != nil {
		t.Fatal(err)
	}
	expires := time.Unix(1, 0)
	if err := prompter.DeviceCode(context.Background(), flow.DeviceCodePrompt{Title: "Device", Message: "Authorize", Code: "ABCD", ExpiresAt: &expires}); err != nil {
		t.Fatal(err)
	}
	if err := prompter.OpenURL(context.Background(), "https://example.com"); err != nil || !opened {
		t.Fatalf("open URL = %v, %v", opened, err)
	}
	progress := prompter.Progress("Working")
	progress.Fail("Failed safely")
	if err := prompter.Outro(context.Background(), "Done"); err != nil {
		t.Fatal(err)
	}
	if err := prompter.Close(); err != nil {
		t.Fatal(err)
	}
	if text := output.String(); !strings.Contains(text, "ABCD") || !strings.Contains(text, "Failed safely") || !strings.Contains(text, "Done") {
		t.Fatalf("output = %q", text)
	}
}
