package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunSetupClientWritesClientEnv(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary home: %v", err)
	}
	secretFile := filepath.Join(dir, "secrets")
	secret := "abcdefghijklmnopqrstuvwxyz123456"
	if err := os.WriteFile(secretFile, []byte("bob = "+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = runSetup(context.Background(), &stdout, ioDiscard{}, []string{
		"client",
		"--client", "bob",
		"--endpoint", "unix:///run/hf-broker/agent.sock",
		"--secret-file", secretFile,
		"--home-dir", dir,
	})
	if err != nil {
		t.Fatalf("runSetup(client) error = %v", err)
	}
	path := filepath.Join(dir, ".config", "hf-broker", "client.env")
	data, err := os.ReadFile(path) // #nosec G304 -- path is in a test temp directory.
	if err != nil {
		t.Fatalf("read client env: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "HF_BROKER_ENDPOINT='unix:///run/hf-broker/agent.sock'") {
		t.Fatalf("client env missing endpoint: %q", text)
	}
	if !strings.Contains(text, "HF_BROKER_SHARED_SECRET='"+secret+"'") {
		t.Fatalf("client env missing secret: %q", text)
	}
	if strings.Contains(stdout.String(), secret) {
		t.Fatalf("setup client stdout leaked secret: %q", stdout.String())
	}
}

func TestParseSetupClientValidation(t *testing.T) {
	_, err := parseSetupClient(ioDiscard{}, []string{"--client", "agent-a", "--endpoint", "unix:///run/hf-broker/agent.sock"})
	if err == nil || !strings.Contains(err.Error(), "--secret-file") {
		t.Fatalf("parseSetupClient() error = %v, want secret-file requirement", err)
	}
	_, err = parseSetupClient(ioDiscard{}, []string{"extra"})
	if err == nil || !strings.Contains(err.Error(), "positional") {
		t.Fatalf("parseSetupClient() positional error = %v", err)
	}
}
