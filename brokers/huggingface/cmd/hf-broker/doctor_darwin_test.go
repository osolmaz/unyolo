//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinDoctorIsolationReportsUnsafeRootAgent(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := runWithArgs(context.Background(), os.Getenv, &stdout, &stderr, []string{
		"doctor", "isolation",
		"--agent-uid", "0",
		"--token-file", token,
		"--json",
	})
	var exitErr exitError
	if !errors.As(err, &exitErr) || exitErr.code != 1 {
		t.Fatalf("runWithArgs() error = %#v, want exit code 1", err)
	}
	if strings.Contains(stdout.String(), "hf_secret_value") || strings.Contains(stderr.String(), "hf_secret_value") {
		t.Fatalf("doctor output leaked token value")
	}
	var payload struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		t.Fatalf("decode doctor JSON: %v\n%s", err, stdout.String())
	}
	if payload.Status != "unsafe" {
		t.Fatalf("status = %q, want unsafe", payload.Status)
	}
}

func TestDarwinDoctorDefaultChecksCurrentProcess(t *testing.T) {
	cmd, err := parseDoctorIsolation(ioDiscard{}, nil)
	if err != nil {
		t.Fatalf("parseDoctorIsolation() error = %v", err)
	}
	if cmd.options.AgentPID != os.Getpid() {
		t.Fatalf("agent PID = %d, want current process PID %d", cmd.options.AgentPID, os.Getpid())
	}
	if cmd.options.AgentUser != "" || cmd.options.AgentUIDSet {
		t.Fatalf("agent identity = user %q uidSet %v, want implicit current process", cmd.options.AgentUser, cmd.options.AgentUIDSet)
	}
}

func TestDarwinDoctorIsolationProbeOutputsOnlyBooleans(t *testing.T) {
	dir := t.TempDir()
	token := filepath.Join(dir, "hf-token")
	if err := os.WriteFile(token, []byte("hf_secret_value"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := runWithArgs(context.Background(), os.Getenv, &stdout, ioDiscard{}, []string{
		"__doctor-isolation-probe",
		"--token-file", token,
	}); err != nil {
		t.Fatalf("probe error = %v", err)
	}
	if strings.Contains(stdout.String(), "hf_secret_value") {
		t.Fatalf("probe output leaked token value")
	}
	if !strings.Contains(stdout.String(), "token_file_readable") {
		t.Fatalf("probe output = %q, want JSON booleans", stdout.String())
	}
}

func TestDarwinExitCodeForRunWritesExitErrorMessage(t *testing.T) {
	var stderr bytes.Buffer
	code := exitCodeForRun(exitError{code: 64, message: "bad usage"}, &stderr)
	if code != 64 {
		t.Fatalf("code = %d, want 64", code)
	}
	if !strings.Contains(stderr.String(), "bad usage") {
		t.Fatalf("stderr = %q, want message", stderr.String())
	}
}

func TestDarwinExitCodeForRunWritesGenericError(t *testing.T) {
	var stderr bytes.Buffer
	code := exitCodeForRun(errors.New("boom"), &stderr)
	if code != 1 {
		t.Fatalf("code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "boom") {
		t.Fatalf("stderr = %q, want error", stderr.String())
	}
}
