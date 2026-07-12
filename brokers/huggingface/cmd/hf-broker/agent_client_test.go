package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func testAgentOperation(state agentv1.State) agentv1.Operation {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	return agentv1.Operation{APIVersion: agentv1.APIVersion, ID: "op_test", Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "one",
		Operation: "repo.create", Target: json.RawMessage(`{"kind":"repo"}`), Arguments: json.RawMessage(`{"private":true}`), State: state,
		Revision: 2, CreatedAt: now, UpdatedAt: now, Presentation: agentv1.Presentation{Title: "Create", Summary: "Create alice/data"}}
}
