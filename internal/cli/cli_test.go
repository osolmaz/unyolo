package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
)

func TestAppHelpDispatchAndSuggestions(t *testing.T) {
	called := false
	app := testApp(func(_ context.Context, args []string, stdout, _ io.Writer) error {
		called = true
		if len(args) != 0 {
			return Usage(errors.New("serve does not accept positional arguments"))
		}
		_, err := io.WriteString(stdout, "served\n")
		return err
	})
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"system"}, {"system", "--help"}, {"help", "system", "serve"}, {"system", "serve", "--help"}} {
		var stdout, stderr bytes.Buffer
		if err := app.Run(t.Context(), args, &stdout, &stderr); err != nil {
			t.Fatalf("Run(%v) = %v", args, err)
		}
		if !strings.Contains(stdout.String(), "Usage:") || stderr.Len() != 0 {
			t.Fatalf("Run(%v) stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if err := app.Run(t.Context(), []string{"system", "serve"}, &stdout, &stderr); err != nil || !called || stdout.String() != "served\n" {
		t.Fatalf("dispatch stdout=%q called=%v err=%v", stdout.String(), called, err)
	}
	err := app.Run(t.Context(), []string{"systm"}, &stdout, &stderr)
	var usage *UsageError
	if !errors.As(err, &usage) || usage.CommandPath != "tool" || !strings.Contains(err.Error(), `did you mean "system"`) {
		t.Fatalf("top-level suggestion = %#v", err)
	}
	err = app.Run(t.Context(), []string{"system", "srve"}, &stdout, &stderr)
	if !errors.As(err, &usage) || usage.CommandPath != "tool system" || !strings.Contains(err.Error(), `did you mean "serve"`) {
		t.Fatalf("nested suggestion = %#v", err)
	}
	err = app.Run(t.Context(), []string{"help", "missing"}, &stdout, &stderr)
	if !errors.As(err, &usage) || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown help target = %#v", err)
	}
	err = app.Run(t.Context(), []string{"help", "system", "serve", "extra"}, &stdout, &stderr)
	if !errors.As(err, &usage) || !strings.Contains(err.Error(), "help does not accept") {
		t.Fatalf("extra help argument = %#v", err)
	}
}

func TestHelpFormattingAndHiddenMetadata(t *testing.T) {
	app := testApp(nil)
	var stdout bytes.Buffer
	if err := app.Run(t.Context(), []string{"help", "system", "serve"}, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	output := stdout.String()
	for _, expected := range []string{
		"Serve one request", "Usage:\n  tool system serve --file FILE [flags]", "--file FILE", "(required)",
		"--count COUNT", "(default: 2)", "-h, --help", "tool system serve --file input.json",
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("help missing %q:\n%s", expected, output)
		}
	}
	if strings.Contains(output, "secret") {
		t.Fatalf("hidden flag leaked:\n%s", output)
	}
	stdout.Reset()
	if err := app.Run(t.Context(), nil, &stdout, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "-v, --version") || strings.Contains(stdout.String(), "__complete") {
		t.Fatalf("root options or hidden command are wrong:\n%s", stdout.String())
	}
}

func TestParseAndCatalogValidation(t *testing.T) {
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Bool("known", false, "known")
	err := Parse(flags, []string{"--unknown"})
	var usage *UsageError
	if !errors.As(err, &usage) {
		t.Fatalf("parse error = %T %v", err, err)
	}
	handler := func(context.Context, []string, io.Writer, io.Writer) error { return nil }
	oneFlag := func(output io.Writer) *flag.FlagSet {
		values := flag.NewFlagSet("one", flag.ContinueOnError)
		values.SetOutput(output)
		values.Bool("known", false, "known")
		return values
	}
	tests := []struct {
		name string
		app  *App
		want string
	}{
		{"bad app", &App{Name: "Bad", Summary: "summary"}, "application name"},
		{"bad command name", validationApp(&Command{Name: "Bad", Summary: "bad", Description: "bad", Run: handler}), "invalid"},
		{"missing summary", validationApp(&Command{Name: "bad", Description: "bad", Run: handler}), "no summary"},
		{"missing handler", validationApp(&Command{Name: "bad", Summary: "bad", Description: "bad"}), "no handler"},
		{"missing description", validationApp(&Command{Name: "bad", Summary: "bad", Run: handler}), "no description"},
		{"flags without set", validationApp(&Command{Name: "bad", Summary: "bad", Description: "bad", RequiredFlags: []string{"missing"}, Run: handler}), "without a flag set"},
		{"unknown required", validationApp(&Command{Name: "bad", Summary: "bad", Description: "bad", Flags: oneFlag, RequiredFlags: []string{"missing"}, Run: handler}), "requires unknown flag"},
		{"unknown hidden", validationApp(&Command{Name: "bad", Summary: "bad", Description: "bad", Flags: oneFlag, HiddenFlags: map[string]bool{"missing": true}, Run: handler}), "hides unknown flag"},
		{"duplicate", &App{Name: "tool", Summary: "summary", Commands: []*Command{{Name: "same", Summary: "one", Description: "one", Run: handler}, {Name: "same", Summary: "two", Description: "two", Run: handler}}}, "duplicate"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.app.Validate(); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Validate() = %v, want %q", err, test.want)
			}
		})
	}
	validHidden := validationApp(&Command{Name: "__internal", Hidden: true, Run: handler})
	if err := validHidden.Validate(); err != nil {
		t.Fatalf("hidden internal command = %v", err)
	}
}

func validationApp(command *Command) *App {
	return &App{Name: "tool", Summary: "summary", Commands: []*Command{command}}
}

func TestCompletionCandidatesAndScripts(t *testing.T) {
	app := testApp(nil)
	for _, test := range []struct {
		words []string
		want  []string
	}{
		{[]string{"sys"}, []string{"system"}},
		{[]string{"system", ""}, []string{"serve"}},
		{[]string{"system", "serve", "--f"}, []string{"--file"}},
	} {
		if got := app.completionCandidates(test.words); strings.Join(got, ",") != strings.Join(test.want, ",") {
			t.Fatalf("completion(%v) = %v, want %v", test.words, got, test.want)
		}
	}
	if got := app.completionCandidates([]string{"system", "serve", "--s"}); len(got) != 0 {
		t.Fatalf("hidden flag completion = %v", got)
	}
	for _, shell := range []string{"bash", "zsh", "fish"} {
		var stdout bytes.Buffer
		if err := app.Run(t.Context(), []string{"completion", shell}, &stdout, io.Discard); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "tool __complete") {
			t.Fatalf("%s completion script = %q", shell, stdout.String())
		}
	}
	var stdout bytes.Buffer
	if err := app.Run(t.Context(), []string{"__complete", "system", emptyCompletionWord}, &stdout, io.Discard); err != nil || stdout.String() != "serve\n" {
		t.Fatalf("empty current-word completion = %q, %v", stdout.String(), err)
	}
}

func testApp(handler Handler) *App {
	if handler == nil {
		handler = func(context.Context, []string, io.Writer, io.Writer) error { return nil }
	}
	serveFlags := func(output io.Writer) *flag.FlagSet {
		flags := flag.NewFlagSet("tool system serve", flag.ContinueOnError)
		flags.SetOutput(output)
		flags.String("file", "", "input `FILE`")
		flags.Int("count", 2, "request `COUNT`")
		flags.String("secret", "", "internal `VALUE`")
		return flags
	}
	return &App{
		Name: "tool", Summary: "Tool summary.", Description: "Tool description.", Version: "v1.2.3", EnableCompletion: true,
		Commands: []*Command{{
			Name: "system", Summary: "System commands", Description: "System commands.", Children: []*Command{{
				Name: "serve", Summary: "Serve one request", Description: "Serve one request from a file.", Usage: "--file FILE [flags]",
				Flags: serveFlags, RequiredFlags: []string{"file"}, HiddenFlags: map[string]bool{"secret": true},
				Examples: []string{"tool system serve --file input.json"}, Run: handler,
			}},
		}},
	}
}
