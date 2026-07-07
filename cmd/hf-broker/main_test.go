package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRunFailsClosedWhenRequiredEnvMissing(t *testing.T) {
	clearBrokerEnv(t)
	t.Setenv("HF_BROKER_HF_TOKEN", "")
	t.Setenv("HF_BROKER_SHARED_SECRET", "")
	err := runWithContext(context.Background(), os.Getenv, ioDiscard{}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "HF_BROKER_HF_TOKEN") {
		t.Fatalf("run() error = %v, want missing token", err)
	}
}

func TestRunFailsOnMissingScopeFileWithoutLeakingToken(t *testing.T) {
	clearBrokerEnv(t)
	t.Setenv("HF_BROKER_HF_TOKEN", "hf_token_value")
	t.Setenv("HF_BROKER_SHARED_SECRET", "abcdefghijklmnopqrstuvwxyz123456")
	t.Setenv("HF_BROKER_SCOPE_FILE", "does-not-exist.json")
	t.Setenv("HF_BROKER_PORT", "65530")
	err := runWithContext(context.Background(), os.Getenv, ioDiscard{}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "read scope file") {
		t.Fatalf("run() error = %v, want missing scope", err)
	}
	if strings.Contains(err.Error(), os.Getenv("HF_BROKER_HF_TOKEN")) {
		t.Fatalf("run() leaked token in error: %v", err)
	}
}

func clearBrokerEnv(t *testing.T) {
	t.Helper()
	suffixes := []string{
		"HF_TOKEN",
		"HF_TOKEN_FILE",
		"SHARED_SECRET",
		"SECRETS_FILE",
		"BIND_ADDR",
		"PORT",
		"SCOPE_FILE",
		"STATE_DIR",
		"MAX_PACK_BYTES",
		"HF_TIMEOUT",
		"TELEGRAM_BOT_TOKEN",
		"TELEGRAM_CHAT_ID",
	}
	for _, suffix := range suffixes {
		t.Setenv("HF_BROKER_"+suffix, "")
		t.Setenv("BROKER_"+suffix, "")
	}
}

func TestRunWithContextStartsAndStops(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(scopePath, []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":      "hf_token_value",
		"HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_SCOPE_FILE":    scopePath,
		"HF_BROKER_STATE_DIR":     filepath.Join(dir, "state"),
		"HF_BROKER_PORT":          strconv.Itoa(port),
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	var stdout, stderr bytes.Buffer
	go func() {
		errs <- runWithContext(ctx, func(key string) string { return env[key] }, &stdout, &stderr)
	}()
	waitForHealth(t, port)
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("runWithContext() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runWithContext() did not stop")
	}
	if !strings.Contains(stderr.String(), "hf-broker stopped") {
		t.Fatalf("stderr = %q, want stop message", stderr.String())
	}
}

func TestRunWithContextReturnsListenError(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(scopePath, []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":      "hf_token_value",
		"HF_BROKER_SHARED_SECRET": "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_SCOPE_FILE":    scopePath,
		"HF_BROKER_STATE_DIR":     filepath.Join(dir, "state"),
		"HF_BROKER_PORT":          strconv.Itoa(port),
	}
	err = runWithContext(context.Background(), func(key string) string { return env[key] }, ioDiscard{}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "bind") {
		t.Fatalf("runWithContext() error = %v, want bind failure", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()
	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHealth(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("server did not become healthy")
}
