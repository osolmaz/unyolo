package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/deployment/flow"
	unyolocli "github.com/osolmaz/unyolo/internal/cli"
)

func TestCLIHelpGoldenFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{"root", []string{"--help"}},
		{"setup", []string{"setup", "--help"}},
		{"system", []string{"system", "--help"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run(t.Context(), test.args, &stdout, &stderr); err != nil {
				t.Fatal(err)
			}
			expected, err := os.ReadFile(filepath.Join("testdata", test.name+"-help.txt"))
			if err != nil {
				t.Fatal(err)
			}
			if stdout.String() != string(expected) || stderr.Len() != 0 {
				t.Fatalf("stdout diff\n--- got ---\n%s--- want ---\n%s--- stderr ---\n%s", stdout.String(), expected, stderr.String())
			}
		})
	}
}

func TestEveryVisibleCommandHasWorkingHelp(t *testing.T) {
	app := newCLIApplication()
	if err := app.Validate(); err != nil {
		t.Fatal(err)
	}
	var paths [][]string
	var collect func([]string, []*unyolocli.Command)
	collect = func(parent []string, commands []*unyolocli.Command) {
		for _, command := range commands {
			if command.Hidden {
				continue
			}
			path := append(append([]string(nil), parent...), command.Name)
			paths = append(paths, path)
			collect(path, command.Children)
		}
	}
	collect(nil, app.Commands)
	paths = append(paths,
		[]string{"completion"}, []string{"completion", "bash"}, []string{"completion", "zsh"}, []string{"completion", "fish"},
	)
	for _, path := range paths {
		t.Run(strings.Join(path, "_"), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			args := append(append([]string(nil), path...), "--help")
			if err := run(t.Context(), args, &stdout, &stderr); err != nil {
				t.Fatalf("help error = %v", err)
			}
			if !strings.Contains(stdout.String(), "Usage:") || stderr.Len() != 0 {
				t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIHelpHidesInternalPlumbing(t *testing.T) {
	var stdout bytes.Buffer
	for _, args := range [][]string{{"--help"}, {"setup", "--help"}, {"system", "--help"}} {
		stdout.Reset()
		if err := run(t.Context(), args, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		for _, hidden := range []string{"bootstrap-stage", "setup-worker", "__complete"} {
			if strings.Contains(stdout.String(), hidden) {
				t.Fatalf("%v leaked %q:\n%s", args, hidden, stdout.String())
			}
		}
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"system", "setup-worker", "--help"}, &stdout, &bytes.Buffer{}); err != nil || !strings.Contains(stdout.String(), "--protocol-stdio") {
		t.Fatalf("explicit internal help=%q err=%v", stdout.String(), err)
	}
}

func TestCLICutoverAndUsageExitSemantics(t *testing.T) {
	var usage *unyolocli.UsageError
	for _, args := range [][]string{
		{"setup", "status"}, {"setup", "cancel"}, {"setup", "discard"}, {"setup", "repair"}, {"setup", "reconfigure"}, {"setup", "remove"},
	} {
		err := run(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.As(err, &usage) || exitCode(err) != 2 {
			t.Fatalf("old route %v = %T %v, exit %d", args, err, err, exitCode(err))
		}
	}
	conflict := run(t.Context(), []string{"setup", "--resume", "session", "--new"}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.As(conflict, &usage) || !strings.Contains(conflict.Error(), "cannot be used together") {
		t.Fatalf("setup flag conflict = %v", conflict)
	}
	if exitCode(errors.New("runtime")) != 1 || exitCode(flow.CancelledError{}) != 130 || exitCode(unyolocli.Usage(errors.New("usage"))) != 2 {
		t.Fatal("exit code classification changed")
	}
	var stdout bytes.Buffer
	if err := run(t.Context(), []string{"--version"}, &stdout, &bytes.Buffer{}); err != nil || strings.TrimSpace(stdout.String()) != version {
		t.Fatalf("--version=%q err=%v", stdout.String(), err)
	}
}

func TestCLIUnknownCommandSuggestion(t *testing.T) {
	err := run(t.Context(), []string{"stats"}, &bytes.Buffer{}, &bytes.Buffer{})
	var usage *unyolocli.UsageError
	if !errors.As(err, &usage) || usage.CommandPath != "unyolo" || !strings.Contains(err.Error(), `did you mean "status"`) {
		t.Fatalf("suggestion = %#v", err)
	}
	err = run(t.Context(), []string{"system", "statuz"}, &bytes.Buffer{}, &bytes.Buffer{})
	if !errors.As(err, &usage) || usage.CommandPath != "unyolo system" || !strings.Contains(err.Error(), `did you mean "status"`) {
		t.Fatalf("nested suggestion = %#v", err)
	}
	var stderr bytes.Buffer
	err = run(t.Context(), []string{"status", "--wat"}, &bytes.Buffer{}, &stderr)
	if !errors.As(err, &usage) || usage.CommandPath != "unyolo status" || stderr.Len() != 0 {
		t.Fatalf("unknown flag = %#v, stderr=%q", err, stderr.String())
	}
}

func TestTopLevelLifecycleCommandsReachTheirHandlers(t *testing.T) {
	for _, command := range []string{"repair", "reconfigure", "remove"} {
		err := run(t.Context(), []string{command, "--accessible"}, &bytes.Buffer{}, &bytes.Buffer{})
		var usage *unyolocli.UsageError
		if err == nil || errors.As(err, &usage) || strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("%s did not reach lifecycle handler: %T %v", command, err, err)
		}
	}
}

func TestCLICompletionScripts(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		var stdout bytes.Buffer
		if err := run(t.Context(), []string{"completion", shell}, &stdout, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(stdout.String(), "unyolo __complete") {
			t.Fatalf("%s completion=%q", shell, stdout.String())
		}
	}
	var stdout bytes.Buffer
	if err := run(t.Context(), []string{"__complete", "sys"}, &stdout, &bytes.Buffer{}); err != nil || stdout.String() != "system\n" {
		t.Fatalf("dynamic completion=%q err=%v", stdout.String(), err)
	}
}
