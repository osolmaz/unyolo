//go:build linux

package setup

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/deployment/flow"
)

func TestTextInputSupportsTierOneKeybindings(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	t.Setenv("FORCE_COLOR", "")
	scripts := []struct {
		name    string
		width   int
		typed   string
		expects string
	}{
		{name: "ctrl+a-then-x-inserts-at-start", width: 60, typed: "world\x01x", expects: "xworld"},
		{name: "ctrl+e-jumps-to-end", width: 80, typed: "hi\x01\x05!", expects: "hi!"},
		{name: "ctrl+u-deletes-to-start", width: 120, typed: "unused\x15good", expects: "good"},
		{name: "ctrl+k-deletes-to-end", width: 60, typed: "keepremove\x01\x06\x06\x06\x06\x0b", expects: "keep"},
		{name: "ctrl+w-deletes-word", width: 80, typed: "one two\x17", expects: "one "},
		{name: "backspace-deletes-char", width: 80, typed: "chart\x08", expects: "char"},
	}
	for _, script := range scripts {
		script := script
		t.Run(script.name, func(t *testing.T) {
			runInputScript(t, script.width, script.typed, script.expects)
		})
	}
}

func runInputScript(t *testing.T, width int, typed, expected string) {
	t.Helper()
	master, slave := openPTY(t)
	defer func() { _ = master.Close(); _ = slave.Close() }()
	input, sendInput, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close(); _ = sendInput.Close() }()
	var captured bytes.Buffer
	drainDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&captured, master)
		close(drainDone)
	}()
	prompter := New(Options{Input: input, Output: slave, Width: width, Height: 24})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := make(chan struct {
		value string
		err   error
	}, 1)
	go func() {
		value, err := prompter.Text(ctx, flow.Prompt{Message: "Name"})
		result <- struct {
			value string
			err   error
		}{value, err}
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := sendInput.Write([]byte(typed)); err != nil {
		t.Fatal(err)
	}
	// Give the input model a chance to process every keystroke before we submit.
	time.Sleep(100 * time.Millisecond)
	if _, err := sendInput.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}
	if err := sendInput.Close(); err != nil {
		t.Fatal(err)
	}
	got := <-result
	if err := prompter.Close(); err != nil {
		t.Fatal(err)
	}
	_ = slave.Close()
	select {
	case <-drainDone:
	case <-time.After(time.Second):
		_ = master.Close()
		<-drainDone
	}
	if got.err != nil {
		t.Fatalf("text prompt error: %v", got.err)
	}
	if got.value != expected {
		t.Fatalf("value = %q, want %q", got.value, expected)
	}
	_ = captured.String()
}
