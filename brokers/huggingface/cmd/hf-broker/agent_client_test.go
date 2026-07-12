package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
)

const agentClientTestSecret = "abcdefghijklmnopqrstuvwxyz123456"

func TestRunAgentClientRepoCreateWaitsForApproval(t *testing.T) {
	var eventCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+agentClientTestSecret {
			t.Fatalf("authorization = %q", r.Header.Get("Authorization"))
		}
		operation := testAgentOperation(agentv1.StatePending)
		if strings.HasSuffix(r.URL.Path, "/events") {
			eventCalls.Add(1)
			operation = testAgentOperation(agentv1.StateSucceeded)
			operation.Revision = 4
			operation.Result = json.RawMessage(`{"repo_id":"alice/data"}`)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(operation)
	}))
	defer server.Close()
	getenv := func(name string) string {
		switch name {
		case "HF_BROKER_URL":
			return server.URL
		case "HF_BROKER_SHARED_SECRET":
			return agentClientTestSecret
		default:
			return ""
		}
	}
	var stdout, stderr bytes.Buffer
	err := runAgentClient(context.Background(), getenv, &stdout, &stderr, []string{"repo", "create", "alice/data", "--type", "dataset", "--idempotency-key", "create-data"})
	if err != nil {
		t.Fatal(err)
	}
	if eventCalls.Load() != 1 || !strings.Contains(stdout.String(), "alice/data") || !strings.Contains(stderr.String(), "Approval requested") {
		t.Fatalf("stdout=%q stderr=%q calls=%d", stdout.String(), stderr.String(), eventCalls.Load())
	}
}

func TestRunMCPListsAndCallsTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(testAgentOperation(agentv1.StatePending))
	}))
	defer server.Close()
	getenv := func(name string) string {
		if name == "HF_BROKER_URL" {
			return server.URL
		}
		if name == "HF_BROKER_SHARED_SECRET" {
			return agentClientTestSecret
		}
		return ""
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hf_repo_create","arguments":{"repo_id":"alice/data","type":"dataset","private":true,"reason":"create","idempotency_key":"one","wait_seconds":0}}}`,
	}, "\n") + "\n"
	var output bytes.Buffer
	if err := runMCP(context.Background(), getenv, strings.NewReader(input), &output, &bytes.Buffer{}, nil); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "hf_repo_create") || !strings.Contains(lines[2], `"state":"pending"`) {
		t.Fatalf("MCP output = %q", output.String())
	}
}

func TestLoadAgentClientRejectsMissingCredential(t *testing.T) {
	_, err := loadAgentClient(func(name string) string {
		if name == "HF_BROKER_URL" {
			return "http://127.0.0.1:8080"
		}
		return ""
	})
	if err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("error = %v", err)
	}
}

func TestRunAgentClientOperationCommands(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := testAgentOperation(agentv1.StateSucceeded)
		operation.Result = json.RawMessage(`{"repo_id":"alice/data"}`)
		_ = json.NewEncoder(w).Encode(operation)
	}))
	defer server.Close()
	getenv := agentClientTestEnv(server.URL)
	for _, action := range []string{"get", "wait"} {
		var output bytes.Buffer
		if err := runAgentClient(context.Background(), getenv, &output, &bytes.Buffer{}, []string{"operation", action, "--json", "op_test"}); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		if !strings.Contains(output.String(), `"state": "succeeded"`) {
			t.Fatalf("%s output = %q", action, output.String())
		}
	}
	if err := runAgentClient(context.Background(), getenv, &bytes.Buffer{}, &bytes.Buffer{}, []string{"unknown"}); err == nil {
		t.Fatal("unknown client command accepted")
	}
}

func TestAgentClientConfigurationAndResponseErrors(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "secret")
	if err := os.WriteFile(secretFile, []byte(agentClientTestSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := loadAgentClient(func(name string) string {
		switch name {
		case "MLCLAW_HF_BROKER_URL":
			return "http://127.0.0.1:8080/"
		case "MLCLAW_HF_BROKER_AGENT_SECRET_FILE":
			return secretFile
		default:
			return ""
		}
	})
	if err != nil || client.secret != agentClientTestSecret {
		t.Fatalf("file client = %#v, %v", client, err)
	}
	for _, value := range []string{"", "ftp://example.test", "http://user@example.test", "http://example.test?q=1"} {
		if _, err := parseAgentBaseURL(value); err == nil {
			t.Fatalf("URL %q accepted", value)
		}
	}
	if _, err := loadAgentSecret(func(name string) string {
		if strings.HasSuffix(name, "_FILE") {
			return "/missing"
		}
		return ""
	}); err == nil {
		t.Fatal("missing secret file accepted")
	}
	if _, err := decodeAgentResponse(http.StatusForbidden, []byte(`{"error":{"code":"denied","message":"no"}}`)); err == nil || err.Error() != "no" {
		t.Fatalf("structured error = %v", err)
	}
	if _, err := decodeAgentResponse(http.StatusBadGateway, []byte(`bad`)); err == nil {
		t.Fatal("HTTP error accepted")
	}
	if _, err := decodeAgentResponse(http.StatusOK, []byte(`{}`)); err == nil {
		t.Fatal("invalid operation accepted")
	}
}

func TestRepoCreateOptionsAndTerminalOutput(t *testing.T) {
	invalid := [][]string{
		{},
		{"alice/data", "--type", "bad"},
		{"alice/data", "--type", "dataset", "--sdk", "docker"},
		{"alice/data", "--reason", ""},
		{"alice/data", "extra"},
	}
	for _, args := range invalid {
		if _, err := parseRepoCreateClientOptions(args); err == nil {
			t.Fatalf("options accepted: %v", args)
		}
	}
	options, err := parseRepoCreateClientOptions([]string{"--type", "space", "--public", "alice/app"})
	if err != nil || options.sdk != "docker" || options.private {
		t.Fatalf("Space options = %#v, %v", options, err)
	}
	request, err := repoCreateSubmitRequest(&repoCreateClientOptions{repoID: "alice/data", repoType: "dataset", private: true, reason: "create"})
	if err != nil || request.IdempotencyKey == "" {
		t.Fatalf("generated request = %#v, %v", request, err)
	}
	if _, err := repoCreateSubmitRequest(&repoCreateClientOptions{repoID: "bad"}); err == nil {
		t.Fatal("bad repo ID accepted")
	}
	operation := testAgentOperation(agentv1.StateFailed)
	operation.Error = &agentv1.OperationError{Code: "failed", Message: "failed safely"}
	if err := printClientOperation(&bytes.Buffer{}, operation, false); err == nil {
		t.Fatal("terminal failure printed as success")
	}
	if err := printClientOperation(&bytes.Buffer{}, operation, true); err != nil {
		t.Fatalf("JSON terminal output: %v", err)
	}
	if _, err := randomClientID(); err != nil {
		t.Fatal(err)
	}
}

func TestMCPProtocolErrorsAndOperationTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		operation := testAgentOperation(agentv1.StateSucceeded)
		_ = json.NewEncoder(w).Encode(operation)
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hf_operation_get", "hf_operation_wait"} {
		operation, err := callMCPTool(context.Background(), client, mcpToolCall{Name: name, Arguments: json.RawMessage(`{"operation_id":"op_test"}`)})
		if err != nil || operation.ID != "op_test" {
			t.Fatalf("%s = %#v, %v", name, operation, err)
		}
	}
	if _, err := callMCPTool(context.Background(), client, mcpToolCall{Name: "unknown", Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("unknown MCP tool accepted")
	}
	if _, err := mcpRepoCreateRequest(mcpRepoCreateInput{}); err == nil {
		t.Fatal("missing MCP privacy accepted")
	}
	if _, err := callMCPRepoCreate(context.Background(), client, json.RawMessage(`{"repo_id":"alice/data","type":"dataset","private":true,"reason":"create","idempotency_key":"bad-wait","wait_seconds":901}`)); err == nil {
		t.Fatal("oversized repository wait accepted")
	}
	private := true
	if _, err := mcpRepoCreateRequest(mcpRepoCreateInput{RepoID: "bad", Private: &private}); err == nil {
		t.Fatal("bad MCP repo accepted")
	}
	space, err := mcpRepoCreateRequest(mcpRepoCreateInput{RepoID: "alice/app", Type: "space", Private: &private, Reason: "create", IdempotencyKey: "space"})
	if err != nil || !strings.Contains(string(space.Arguments), `"sdk":"docker"`) {
		t.Fatalf("Space MCP default = %s, %v", space.Arguments, err)
	}
	largeID := json.RawMessage(`9007199254740993`)
	response := handleMCPRequest(context.Background(), client, mcpRequest{JSONRPC: "2.0", ID: largeID, Method: "unknown"})
	if response.Error == nil || response.Error.Code != -32601 {
		t.Fatalf("unknown method response = %#v", response)
	}
	encoded, _ := json.Marshal(response)
	if !strings.Contains(string(encoded), `"id":9007199254740993`) {
		t.Fatalf("response ID changed: %s", encoded)
	}
	var output bytes.Buffer
	if err := runMCP(context.Background(), agentClientTestEnv(server.URL), strings.NewReader("bad\n"), &output, &bytes.Buffer{}, nil); err != nil || !strings.Contains(output.String(), "-32700") {
		t.Fatalf("parse response = %q, %v", output.String(), err)
	}
	if err := runMCP(context.Background(), agentClientTestEnv(server.URL), strings.NewReader(""), &output, &bytes.Buffer{}, []string{"bad"}); err == nil {
		t.Fatal("MCP args accepted")
	}
}

func TestMCPWaitDeadlineReturnsResumableOperation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(testAgentOperation(agentv1.StatePending))
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	private := true
	for _, call := range []mcpToolCall{
		{Name: "hf_operation_wait", Arguments: json.RawMessage(`{"operation_id":"op_test","wait_seconds":1}`)},
		{Name: "hf_repo_create", Arguments: mustJSON(t, mcpRepoCreateInput{RepoID: "alice/data", Type: "dataset", Private: &private, Reason: "create", IdempotencyKey: "create", WaitSeconds: 1})},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		operation, callErr := callMCPTool(ctx, client, call)
		cancel()
		if callErr != nil || operation.ID != "op_test" || operation.State != agentv1.StatePending {
			t.Fatalf("%s = %#v, %v", call.Name, operation, callErr)
		}
	}
}

func mustJSON(t *testing.T, value any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func agentClientTestEnv(serverURL string) func(string) string {
	return func(name string) string {
		if name == "HF_BROKER_URL" {
			return serverURL
		}
		if name == "HF_BROKER_SHARED_SECRET" {
			return agentClientTestSecret
		}
		return ""
	}
}

func testAgentOperation(state agentv1.State) agentv1.Operation {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	return agentv1.Operation{APIVersion: agentv1.APIVersion, ID: "op_test", Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "one",
		Operation: "repo.create", Target: json.RawMessage(`{"kind":"repo"}`), Arguments: json.RawMessage(`{"private":true}`), State: state,
		Revision: 2, CreatedAt: now, UpdatedAt: now, Presentation: agentv1.Presentation{Title: "Create", Summary: "Create alice/data"}}
}
