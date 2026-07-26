package setup

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/deployment/flow"
)

func TestAccessibleRendererNeverEchoesSecret(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	prompter := New(Options{Input: strings.NewReader("credential-canary\n"), Output: &output, Accessible: true, Width: 60})
	if err := prompter.Intro(context.Background(), "BrokerKit setup"); err != nil {
		t.Fatal(err)
	}
	secret, err := prompter.Secret(context.Background(), flow.Prompt{Message: "Provider token", Required: true})
	if err != nil {
		t.Fatalf("Secret() error = %v", err)
	}
	defer clear(secret)
	if string(secret) != "credential-canary" {
		t.Fatalf("secret = %q", secret)
	}
	if err := prompter.Close(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "credential-canary") || strings.Contains(output.String(), "\x1b") {
		t.Fatalf("unsafe output: %q", output.String())
	}
	if !strings.Contains(output.String(), "configured") {
		t.Fatalf("output lacks fixed completion marker: %q", output.String())
	}
}

func TestPlainProgressIsStable(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	prompter := New(Options{Output: &output, Accessible: true, Width: 24})
	progress := prompter.Progress("Downloading the signed BrokerKit runtime bundle")
	progress.Update("Verifying bundle")
	progress.Stop("Verified bundle")
	if err := prompter.Close(); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if !strings.Contains(text, "…") || !strings.Contains(text, "✓ Verified bundle") || strings.Contains(text, "\r") {
		t.Fatalf("progress output = %q", text)
	}
}

func TestRendererSanitizesAdapterControlCharacters(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var output bytes.Buffer
	prompter := New(Options{Output: &output, Accessible: true})
	if err := prompter.Note(context.Background(), "safe\x1b[31m\x00text", "Adapter"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b") || strings.ContainsRune(output.String(), '\x00') {
		t.Fatalf("control character reached output: %q", output.String())
	}
}
