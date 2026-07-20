package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/osolmaz/brokerkit/agent/v1"
)

const mcpHelperEnvironment = "BROKERKIT_HF_MCP_HELPER"

func TestHFMCPSHelperProcess(t *testing.T) {
	if os.Getenv(mcpHelperEnvironment) != "1" {
		return
	}
	if err := runMCP(context.Background(), os.Getenv, os.Stdin, os.Stdout, os.Stderr, nil); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

func TestMCPSubprocessRecoversLostSubmissionAcrossRestarts(t *testing.T) {
	operation := testAgentOperation(agentv1.StatePending)
	operation.IdempotencyKey = "lost-response"
	var state struct {
		sync.Mutex
		submissions int
		loseFirst   bool
	}
	state.loseFirst = true
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		state.Lock()
		defer state.Unlock()
		if request.Header.Get("Authorization") != "Bearer "+agentClientTestSecret {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/.well-known/brokerkit-agent":
			writeAgentJSON(writer, agentv1.Descriptor{APIVersion: agentv1.APIVersion, Operations: []string{"repo.create"},
				Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "huggingface", CredentialKind: "fine_grained_user_token", Generation: 1, VerificationState: "valid"}})
		case request.Method == http.MethodPost && request.URL.Path == "/api/agent/v1/operations":
			state.submissions++
			if state.loseFirst {
				state.loseFirst = false
				hijacker, ok := writer.(http.Hijacker)
				if !ok {
					t.Fatal("test server cannot drop committed response")
				}
				connection, _, err := hijacker.Hijack()
				if err != nil {
					t.Fatal(err)
				}
				_ = connection.Close()
				return
			}
			writeAgentJSON(writer, operation)
		case request.Method == http.MethodGet && request.URL.Path == "/api/agent/v1/operations":
			if request.URL.Query().Get("idempotency_key") != operation.IdempotencyKey {
				t.Errorf("recovery query = %q", request.URL.RawQuery)
			}
			writeAgentJSON(writer, operationSummaryPage(operation))
		case request.Method == http.MethodGet && request.URL.Path == "/api/agent/v1/operations/"+operation.ID:
			writeAgentJSON(writer, operation)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	submit := mcpCallLine(1, "hf_repo_create", `{"target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"create","request_id":"lost-response"}`)
	first := runHFMCPSProcess(t, server.URL, submit)
	if !strings.Contains(first, `"isError":true`) {
		t.Fatalf("lost submission response = %s", first)
	}

	recovered := runHFMCPSProcess(t, server.URL, mcpCallLine(2, "hf_operation_list", `{"request_id":"lost-response","limit":1}`))
	if !strings.Contains(recovered, `"request_id":"lost-response"`) || !strings.Contains(recovered, `"id":"op_test"`) {
		t.Fatalf("recovery response = %s", recovered)
	}

	state.Lock()
	operation.State = agentv1.StateSucceeded
	operation.Revision++
	operation.Result = json.RawMessage(`{"repo_id":"alice/data"}`)
	state.Unlock()
	terminal := runHFMCPSProcess(t, server.URL, mcpCallLine(3, "hf_operation_get", `{"operation_id":"op_test"}`))
	if !strings.Contains(terminal, `"state":"succeeded"`) || !strings.Contains(terminal, `"repo_id":"alice/data"`) {
		t.Fatalf("terminal response = %s", terminal)
	}
	state.Lock()
	defer state.Unlock()
	if state.submissions != 1 {
		t.Fatalf("submissions = %d, want 1", state.submissions)
	}
}

func runHFMCPSProcess(t *testing.T, serverURL, input string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestHFMCPSHelperProcess$")
	command.Env = append(os.Environ(), mcpHelperEnvironment+"=1", "HF_BROKER_AGENT_ENDPOINT="+testTCPEndpoint(serverURL), "HF_BROKER_SHARED_SECRET="+agentClientTestSecret)
	command.Stdin = strings.NewReader(input + "\n")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("MCP subprocess: %v: %s", err, stderr.String())
	}
	return stdout.String()
}

func mcpCallLine(id int, tool, arguments string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, arguments)
}

func operationSummaryPage(operation agentv1.Operation) map[string]any {
	return map[string]any{
		"api_version": agentv1.APIVersion,
		"operations": []map[string]any{{
			"api_version": operation.APIVersion, "id": operation.ID, "broker": operation.Broker,
			"client_id": operation.ClientID, "idempotency_key": operation.IdempotencyKey,
			"operation": operation.Operation, "state": operation.State, "revision": operation.Revision,
			"created_at": operation.CreatedAt, "updated_at": operation.UpdatedAt, "presentation": operation.Presentation,
		}},
		"next_cursor": nil,
	}
}

func writeAgentJSON(writer http.ResponseWriter, value any) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(value)
}
