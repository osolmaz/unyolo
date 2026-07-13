package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunCommandUsesAgentLifecycle(t *testing.T) {
	var submissions int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/agent/v1/operations" {
			submissions++
			_, _ = w.Write([]byte(`{"api_version":"brokerkit.io/agent/v1","id":"op","broker":"sudo-broker","client_id":"bob","idempotency_key":"test","operation":"exec.command","target":{},"arguments":{},"reason":"release","state":"succeeded","revision":2,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:01Z","terminal_at":"2026-01-01T00:00:01Z","presentation":{"title":"run"},"result":{"exit_code":0,"stdout_base64":"c2NhbGVk","stderr_base64":""}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	t.Setenv("SUDO_BROKER_URL", server.URL)
	t.Setenv("SUDO_BROKER_SHARED_SECRET", "sudo-client-secret-abcdefghijklmnopqrstuvwxyz")
	var stdout, stderr bytes.Buffer
	if err := runCommand(t.Context(), []string{"scale", "--as", "root", "--reason", "release", "--operation-id", "test", "--arg-json", "replicas=2"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "scaled" || stderr.Len() != 0 || submissions != 1 {
		t.Fatalf("stdout=%q stderr=%q submissions=%d", stdout.String(), stderr.String(), submissions)
	}
}

func TestCommandClientValidationAndResult(t *testing.T) {
	for _, args := range [][]string{{}, {"scale", "--as", "root"}, {"scale", "--reason", "why"}, {"scale", "--as", "root", "--reason", "why", "--arg-json", "bad"}} {
		if err := runCommand(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("runCommand(%v) succeeded", args)
		}
	}
	t.Setenv("SUDO_BROKER_URL", "https://example.com")
	t.Setenv("SUDO_BROKER_SHARED_SECRET", "sudo-client-secret-abcdefghijklmnopqrstuvwxyz")
	if _, err := loadAgentClient(); err == nil {
		t.Fatal("non-local broker URL accepted")
	}
	result, _ := json.Marshal(map[string]any{"exit_code": 7, "stdout_base64": base64.StdEncoding.EncodeToString([]byte("out")), "stderr_base64": ""})
	if err := writeCommandResult(&bytes.Buffer{}, &bytes.Buffer{}, result); err == nil {
		t.Fatal("non-zero command result accepted")
	}
	if id, err := randomClientID("test-"); err != nil || !strings.HasPrefix(id, "test-") {
		t.Fatalf("id = %q, %v", id, err)
	}
}

func TestRawArgumentsRejectDuplicates(t *testing.T) {
	var values rawArguments
	if err := values.Set("replicas=2"); err != nil {
		t.Fatal(err)
	}
	if err := values.Set("replicas=3"); err == nil {
		t.Fatal("duplicate argument accepted")
	}
}
