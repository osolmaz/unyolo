package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/clienthttp"
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

func TestCredentialRequirementsCommand(t *testing.T) {
	var stdout, stderr strings.Builder
	if err := runWithArgs(context.Background(), os.Getenv, &stdout, &stderr, []string{"credential", "requirements"}); err != nil {
		t.Fatal(err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	var profile struct {
		Version   int    `json:"version"`
		ProfileID string `json:"profile_id"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Version != 1 || profile.ProfileID != "hf-broker-complete-v1" {
		t.Fatalf("unexpected profile: %+v", profile)
	}
}

func TestRunFailsOnMissingScopeFileWithoutLeakingToken(t *testing.T) {
	clearBrokerEnv(t)
	t.Setenv("HF_BROKER_HF_TOKEN", "hf_token_value")
	t.Setenv("HF_BROKER_SHARED_SECRET", "abcdefghijklmnopqrstuvwxyz123456")
	t.Setenv("HF_BROKER_SCOPE_FILE", "/tmp/does-not-exist.json")
	t.Setenv("HF_BROKER_STATE_DIR", "/tmp/hf-broker-test-state")
	t.Setenv("HF_BROKER_AGENT_ENDPOINT", "unix:///tmp/hf-broker-test.sock")
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
		"AGENT_ENDPOINT",
		"DEVELOPMENT",
		"NETWORK_EXPOSURE",
		"OPERATOR_SHARED_SECRET",
		"OPERATOR_SECRETS_FILE",
		"OPERATOR_ENDPOINT",
		"SCOPE_FILE",
		"STATE_DIR",
		"MAX_PACK_BYTES",
		"HF_TIMEOUT",
		"UPSTREAM_HUB_URL",
		"UPSTREAM_ROUTER_URL",
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
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(scopePath, []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	agentEndpoint := "unix://" + filepath.Join(dir, "agent.sock")
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":       "hf_token_value",
		"HF_BROKER_SHARED_SECRET":  "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_SCOPE_FILE":     scopePath,
		"HF_BROKER_STATE_DIR":      filepath.Join(dir, "state"),
		"HF_BROKER_AGENT_ENDPOINT": agentEndpoint,
		"HF_BROKER_DEVELOPMENT":    "true",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errs := make(chan error, 1)
	var stdout, stderr bytes.Buffer
	go func() {
		errs <- runWithContext(ctx, func(key string) string { return env[key] }, &stdout, &stderr)
	}()
	waitForHealth(t, agentEndpoint)
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

func TestRunWithContextStartsOperatorListener(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(dir, "scope.json")
	operatorPath := filepath.Join(dir, "operator-secrets")
	if err := os.WriteFile(scopePath, []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	operatorSecret := "operator-secret-abcdefghijklmnopqrstuvwxyz"
	if err := os.WriteFile(operatorPath, []byte("onur = "+operatorSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agentEndpoint := "unix://" + filepath.Join(dir, "agent.sock")
	operatorEndpoint := "unix://" + filepath.Join(dir, "operator.sock")
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":              "hf_token_value",
		"HF_BROKER_SHARED_SECRET":         "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_SCOPE_FILE":            scopePath,
		"HF_BROKER_STATE_DIR":             filepath.Join(dir, "state"),
		"HF_BROKER_AGENT_ENDPOINT":        agentEndpoint,
		"HF_BROKER_OPERATOR_SECRETS_FILE": operatorPath,
		"HF_BROKER_OPERATOR_ENDPOINT":     operatorEndpoint,
		"HF_BROKER_DEVELOPMENT":           "true",
	}
	ctx, cancel := context.WithCancel(context.Background())
	errs := make(chan error, 1)
	go func() {
		errs <- runWithContext(ctx, func(key string) string { return env[key] }, ioDiscard{}, ioDiscard{})
	}()
	waitForHealth(t, agentEndpoint)
	waitForOperator(t, operatorEndpoint, operatorSecret)
	cancel()
	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("runWithContext() error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runWithContext() did not stop")
	}
}

func TestRunWithContextReturnsListenError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(scopePath, []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = listener.Close()
	}()
	env := map[string]string{
		"HF_BROKER_HF_TOKEN":       "hf_token_value",
		"HF_BROKER_SHARED_SECRET":  "abcdefghijklmnopqrstuvwxyz123456",
		"HF_BROKER_SCOPE_FILE":     scopePath,
		"HF_BROKER_STATE_DIR":      filepath.Join(dir, "state"),
		"HF_BROKER_AGENT_ENDPOINT": "unix://" + socketPath,
		"HF_BROKER_DEVELOPMENT":    "true",
	}
	err = runWithContext(context.Background(), func(key string) string { return env[key] }, ioDiscard{}, ioDiscard{})
	if err == nil || !strings.Contains(err.Error(), "already accepting") {
		t.Fatalf("runWithContext() error = %v, want occupied endpoint failure", err)
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
}

func waitForHealth(t *testing.T, endpointURI string) {
	t.Helper()
	baseURL, client, err := clienthttp.ForEndpoint(endpointURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/healthz")
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

func waitForOperator(t *testing.T, endpointURI, secret string) {
	t.Helper()
	baseURL, client, err := clienthttp.ForEndpoint(endpointURI, nil)
	if err != nil {
		t.Fatal(err)
	}
	url := baseURL + "/.well-known/brokerkit-operator"
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+secret)
		response, err := client.Do(request)
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("operator server did not become ready")
}
