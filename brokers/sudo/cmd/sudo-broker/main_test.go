package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunDispatchAndMainCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"version"}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), version) {
		t.Fatalf("version = %q, %v", stdout.String(), err)
	}
	for _, args := range [][]string{nil, {"unknown"}, {"run"}, {"doctor"}, {"setup"}, {"serve"}} {
		if err := run(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("run(%v) succeeded", args)
		}
	}
	if code := mainCode([]string{"version"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("version exit code = %d", code)
	}
	if err := runSubcommand(t.Context(), "--version", nil, &stdout, &stderr); err != nil {
		t.Fatalf("--version failed: %v", err)
	}
	if err := runSubcommand(t.Context(), "state", []string{"unknown"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("state subcommand error was swallowed")
	}
	if code := mainCode([]string{"unknown"}, &bytes.Buffer{}, &stderr); code != 1 || !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("error exit code = %d, stderr = %q", code, stderr.String())
	}
	if (exitError{code: 7, message: "failed"}).Error() != "failed" {
		t.Fatal("exit error message changed")
	}
}

func TestWriteCommandResultRejectsMalformedResults(t *testing.T) {
	for _, raw := range []json.RawMessage{
		json.RawMessage(`{`),
		json.RawMessage(`{"stdout_base64":"!","stderr_base64":""}`),
		json.RawMessage(`{"stdout_base64":"","stderr_base64":"!"}`),
	} {
		if err := writeCommandResult(&bytes.Buffer{}, &bytes.Buffer{}, raw); err == nil {
			t.Fatalf("malformed result accepted: %s", raw)
		}
	}
}
