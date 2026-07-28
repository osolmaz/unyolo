package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/mcp"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/internal/storage/sealed"
	"github.com/osolmaz/unyolo/mcp/operation"
	"github.com/osolmaz/unyolo/mcp/server"
	"github.com/osolmaz/unyolo/protocol/contract"
)

func mcpTestEnv(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func callGitHubMCP(ctx context.Context, getenv func(string) string, call mcpserver.ToolCall) (any, error) {
	bridge, err := newGitHubMCPBridge(getenv)
	if err != nil {
		return nil, err
	}
	return bridge.Call(ctx, call)
}

func TestMCPAdvertisesOnlyIntersectedDefaultTools(t *testing.T) {
	all := "repo.metadata.read,repo.contents.read,pull_request.create,pull_request.update"
	tools, err := configuredMCPTools(mcpTestEnv(map[string]string{"GH_BROKER_MCP_EXPOSURE_PROFILE": "default", "GH_BROKER_MCP_CLIENT_OPERATIONS": all, "GH_BROKER_MCP_POLICY_OPERATIONS": all, "GH_BROKER_MCP_RUNTIME_OPERATIONS": "repo.metadata.read,pull_request.create"}))
	if err != nil || len(tools) != 6 {
		t.Fatalf("tools=%d err=%v", len(tools), err)
	}
	for _, tool := range tools {
		schema := tool["inputSchema"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatalf("open tool=%#v", tool)
		}
	}
}

func TestMCPDiscoveryIsPagedAndExhaustiveWithoutAdvertisingCatalog(t *testing.T) {
	tools, err := configuredMCPTools(mcpTestEnv(nil))
	if err != nil || len(tools) != 4 {
		t.Fatalf("tools=%d err=%v", len(tools), err)
	}
	resource, err := readMCPResource("github://operations?limit=7")
	if err != nil {
		t.Fatal(err)
	}
	contents := resource["contents"].([]map[string]any)
	text := contents[0]["text"].(string)
	if !strings.Contains(text, `"total":1436`) || !strings.Contains(text, `"next_cursor"`) {
		t.Fatalf("page=%s", text)
	}
}

func TestMCPRejectsUnknownOrUnadvertisedTool(t *testing.T) {
	_, err := callGitHubMCP(t.Context(), mcpTestEnv(nil), mcpserver.ToolCall{Name: "gh_http_request", Arguments: json.RawMessage(`{}`)})
	if err == nil || !strings.Contains(err.Error(), "not advertised") {
		t.Fatalf("err=%v", err)
	}
}

func TestPrepareMCPArgumentModes(t *testing.T) {
	streamDescriptor, _ := opcatalog.ByName("release.repos_upload_release_asset")
	streamInput := mcpOperationInput{
		Target: json.RawMessage(`{"kind":"release","id":9,"owner":"osolmaz","repo":"unyolo"}`), Arguments: json.RawMessage(`{"name":"asset.bin"}`),
		StreamInput: &mcpStreamReference{ID: "stream_012345678901234567890123"},
	}
	if err := prepareMCPArguments(t.Context(), streamDescriptor, &streamInput, operationConnection{}); err != nil || !bytes.Contains(streamInput.Arguments, []byte("stream_input")) {
		t.Fatalf("stream arguments = %s, %v", streamInput.Arguments, err)
	}
	streamInput.StreamInput = nil
	if err := prepareMCPStreamArguments(streamDescriptor, &streamInput); err == nil {
		t.Fatal("missing stream input accepted")
	}

	readDescriptor, _ := opcatalog.ByName("repo.metadata.read")
	readInput := mcpOperationInput{Target: json.RawMessage(`{"kind":"repo","owner":"osolmaz","name":"unyolo"}`), Arguments: json.RawMessage(`{}`)}
	if err := prepareMCPArguments(t.Context(), readDescriptor, &readInput, operationConnection{}); err != nil {
		t.Fatal(err)
	}
	readInput.CredentialSlot = "unexpected"
	if err := prepareMCPArguments(t.Context(), readDescriptor, &readInput, operationConnection{}); err == nil {
		t.Fatal("credential slot accepted for read")
	}

	secretDescriptor, _ := opcatalog.ByName("workflow.actions_create_or_update_repo_secret")
	secretInput := mcpOperationInput{Target: readInput.Target, Arguments: json.RawMessage(`{"secret_name":"TOKEN"}`)}
	if err := prepareMCPSealedArguments(t.Context(), secretDescriptor, &secretInput, operationConnection{}); err == nil {
		t.Fatal("required sealed arguments omitted")
	}

	shared := agentmcp.Input{Target: readInput.Target, Arguments: json.RawMessage(`{}`), Reason: "read", RequestID: "request"}
	if err := prepareGitHubMCPInput(t.Context(), mcpTestEnv(nil), readDescriptor, &shared); err == nil {
		t.Fatal("missing connection accepted")
	}
	shared.StreamInput = json.RawMessage(`{"bad":true}`)
	if err := prepareGitHubMCPInput(t.Context(), mcpTestEnv(nil), readDescriptor, &shared); err == nil {
		t.Fatal("invalid stream input accepted")
	}
}

func TestMCPToolSignatureChangesWithLivePolicyExposure(t *testing.T) {
	values := map[string]string{"GH_BROKER_MCP_EXPOSURE_PROFILE": "default", "GH_BROKER_MCP_CLIENT_OPERATIONS": "repo.metadata.read", "GH_BROKER_MCP_POLICY_OPERATIONS": "repo.metadata.read", "GH_BROKER_MCP_RUNTIME_OPERATIONS": "repo.metadata.read"}
	getenv := mcpTestEnv(values)
	before, err := configuredMCPTools(getenv)
	if err != nil || len(before) != 5 {
		t.Fatalf("before=%d err=%v", len(before), err)
	}
	values["GH_BROKER_MCP_POLICY_OPERATIONS"] = ""
	after, err := configuredMCPTools(getenv)
	if err != nil || len(after) != 4 {
		t.Fatalf("after=%d before=%d err=%v", len(after), len(before), err)
	}
}

func TestMCPToolsRequireAndIntersectAgentDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/unyolo-agent" {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(agentv1.Descriptor{APIVersion: agentv1.APIVersion,
			ContractDigest: contract.AgentV1Digest, BuildID: "test", Operations: []string{"repo.metadata.read"},
			Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "github", CredentialKind: "github_app", Generation: 1, VerificationState: "valid"}})
	}))
	defer server.Close()
	values := map[string]string{
		"GH_BROKER_AGENT_ENDPOINT": ghTestEndpoint(server.URL), "GH_BROKER_SHARED_SECRET": operationTestSecret,
		"GH_BROKER_MCP_EXACT_OPERATIONS": "repo.metadata.read,pull_request.create", "GH_BROKER_MCP_CLIENT_OPERATIONS": "repo.metadata.read,pull_request.create",
		"GH_BROKER_MCP_POLICY_OPERATIONS": "repo.metadata.read,pull_request.create", "GH_BROKER_MCP_RUNTIME_OPERATIONS": "repo.metadata.read,pull_request.create",
	}
	tools, err := discoveredMCPTools(t.Context(), mcpTestEnv(values))
	if err != nil || len(tools) != 1 || tools[0]["name"] != "gh_repo_metadata_read" {
		t.Fatalf("discovered tools = %#v, %v", tools, err)
	}
	if _, err := discoveredMCPTools(t.Context(), mcpTestEnv(nil)); err == nil {
		t.Fatal("missing Agent discovery endpoint was accepted")
	}
}

func TestRunMCPAndJSONRPCDispatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/unyolo-agent" {
			http.NotFound(writer, request)
			return
		}
		_ = json.NewEncoder(writer).Encode(agentv1.Descriptor{APIVersion: agentv1.APIVersion,
			ContractDigest: contract.AgentV1Digest, BuildID: "test", Operations: []string{},
			Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "github", CredentialKind: "github_app", Generation: 1, VerificationState: "valid"}})
	}))
	defer server.Close()
	getenv := mcpTestEnv(map[string]string{
		"GH_BROKER_AGENT_ENDPOINT": ghTestEndpoint(server.URL), "GH_BROKER_SHARED_SECRET": operationTestSecret,
	})
	input := strings.Join([]string{
		`not-json`,
		`{"jsonrpc":"2.0","method":"ping"}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/list"}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"github://operations?limit=2"}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}`,
		`{"jsonrpc":"2.0","id":6,"method":"unknown"}`,
	}, "\n")
	var output bytes.Buffer
	if err := runMCP(t.Context(), getenv, strings.NewReader(input), &output, nil); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"Parse error", `"protocolVersion":"2025-06-18"`, `github://operations?limit=50`, "Invalid tool call", "Method not found"} {
		if !strings.Contains(text, want) {
			t.Fatalf("MCP output missing %q: %s", want, text)
		}
	}
	if err := runMCP(t.Context(), getenv, strings.NewReader(""), &output, []string{"extra"}); err == nil {
		t.Fatal("accepted MCP arguments")
	}
}

func TestMCPTypedToolSubmission(t *testing.T) {
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/api/agent/v1/operations" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
	}))
	defer server.Close()
	env := map[string]string{
		"GH_BROKER_AGENT_ENDPOINT":         ghTestEndpoint(server.URL),
		"GH_BROKER_SHARED_SECRET":          operationTestSecret,
		"GH_BROKER_MCP_EXACT_OPERATIONS":   "repo.metadata.read",
		"GH_BROKER_MCP_CLIENT_OPERATIONS":  "repo.metadata.read",
		"GH_BROKER_MCP_POLICY_OPERATIONS":  "repo.metadata.read",
		"GH_BROKER_MCP_RUNTIME_OPERATIONS": "repo.metadata.read",
	}
	value, err := callGitHubMCP(t.Context(), mcpTestEnv(env), mcpserver.ToolCall{
		Name:      "gh_repo_metadata_read",
		Arguments: json.RawMessage(`{"target":{"kind":"repo","owner":"osolmaz","name":"unyolo"},"arguments":{},"reason":"inspect metadata","request_id":"request-1"}`),
	})
	operation, ok := value.(mcpoperation.Operation)
	if err != nil || !ok || operation.Operation != "repo.metadata.read" {
		t.Fatalf("value=%#v err=%v", value, err)
	}
}

func TestMCPRequestConflictAndRecoveryTools(t *testing.T) {
	operation := githubTestOperation(agentv1.StatePending)
	operation.IdempotencyKey = "same-request"
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/agent/v1/operations":
			writer.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(writer).Encode(map[string]any{"error": map[string]any{
				"code": "idempotency_conflict", "message": "request identity conflicts",
			}})
		case request.Method == http.MethodGet && request.URL.Path == "/api/agent/v1/operations":
			if request.URL.Query().Get("idempotency_key") != operation.IdempotencyKey {
				t.Errorf("recovery query = %q", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(githubOperationSummaryPage(operation))
		case request.Method == http.MethodGet && request.URL.Path == "/api/agent/v1/operations/"+operation.ID:
			_ = json.NewEncoder(writer).Encode(operation)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	env := map[string]string{
		"GH_BROKER_AGENT_ENDPOINT": ghTestEndpoint(server.URL), "GH_BROKER_SHARED_SECRET": operationTestSecret,
		"GH_BROKER_MCP_EXACT_OPERATIONS": "repo.metadata.read", "GH_BROKER_MCP_CLIENT_OPERATIONS": "repo.metadata.read",
		"GH_BROKER_MCP_POLICY_OPERATIONS": "repo.metadata.read", "GH_BROKER_MCP_RUNTIME_OPERATIONS": "repo.metadata.read",
	}
	_, err := callGitHubMCP(t.Context(), mcpTestEnv(env), mcpserver.ToolCall{
		Name:      "gh_repo_metadata_read",
		Arguments: json.RawMessage(`{"target":{"kind":"repo","owner":"osolmaz","name":"unyolo"},"arguments":{},"reason":"inspect","request_id":"same-request"}`),
	})
	var conflict *mcpoperation.RequestIDConflictError
	if !errors.As(err, &conflict) || conflict.Existing.ID != operation.ID || conflict.Existing.RequestID != "same-request" {
		t.Fatalf("conflict = %#v, %v", conflict, err)
	}
	value, err := callGitHubMCP(t.Context(), mcpTestEnv(env), mcpserver.ToolCall{
		Name: "gh_operation_list", Arguments: json.RawMessage(`{"request_id":"same-request","limit":1}`),
	})
	page, ok := value.(mcpoperation.Page)
	if err != nil || !ok || len(page.Operations) != 1 || page.Operations[0].ID != operation.ID {
		t.Fatalf("recovery = %#v, %v", value, err)
	}
	for _, call := range []mcpserver.ToolCall{
		{Name: "gh_operation_get", Arguments: json.RawMessage(`{"operation_id":"op_test"}`)},
		{Name: "gh_operation_wait", Arguments: json.RawMessage(`{"operation_id":"op_test","timeout_seconds":0}`)},
	} {
		value, err = callGitHubMCP(t.Context(), mcpTestEnv(env), call)
		projected, projectedOK := value.(mcpoperation.Operation)
		if err != nil || !projectedOK || projected.ID != operation.ID {
			t.Fatalf("%s = %#v, %v", call.Name, value, err)
		}
	}
}

func githubOperationSummaryPage(operation agentv1.Operation) map[string]any {
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

func TestMCPSealedToolUsesOneTimePayloadBoundary(t *testing.T) {
	const operation = "workflow.actions_create_or_update_repo_secret"
	var submitted []byte
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/agent/v1/sealed-payloads":
			payload, _ := io.ReadAll(request.Body)
			if !bytes.Contains(payload, []byte("Y2FuYXJ5")) {
				t.Errorf("sealed payload = %s", payload)
			}
			writer.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(writer).Encode(sealedstore.Reference{ID: "sealed_012345678901234567890123", Owner: "bob", Purpose: operation,
				RequestKey: "mcp-secret", Digest: strings.Repeat("a", 64), Size: len(payload), ExpiresAt: time.Now().Add(time.Hour).Unix()})
		case "/api/agent/v1/operations":
			submitted, _ = io.ReadAll(request.Body)
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	env := map[string]string{
		"GH_BROKER_AGENT_ENDPOINT": ghTestEndpoint(server.URL), "GH_BROKER_SHARED_SECRET": operationTestSecret,
		"GH_BROKER_MCP_EXACT_OPERATIONS": operation, "GH_BROKER_MCP_CLIENT_OPERATIONS": operation,
		"GH_BROKER_MCP_POLICY_OPERATIONS": operation, "GH_BROKER_MCP_RUNTIME_OPERATIONS": operation,
	}
	_, err := callGitHubMCP(t.Context(), mcpTestEnv(env), mcpserver.ToolCall{
		Name:      "gh_workflow_actions_create_or_update_repo_secret",
		Arguments: json.RawMessage(`{"target":{"kind":"repo","owner":"osolmaz","name":"unyolo"},"arguments":{"secret_name":"DEPLOY_TOKEN"},"sealed_arguments":{"input":{"encrypted_value":"Y2FuYXJ5","key_id":"key-1"}},"reason":"rotate secret","request_id":"mcp-secret"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(submitted, []byte("Y2FuYXJ5")) || !bytes.Contains(submitted, []byte(`"sealed_payload"`)) {
		t.Fatalf("submitted = %s", submitted)
	}
}

func TestMCPOptionalSealedInputDoesNotCreatePayload(t *testing.T) {
	const operation = "organization.update_webhook"
	var submitted []byte
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/v1/operations" {
			t.Fatalf("unexpected route %s", request.URL.Path)
		}
		submitted, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
	}))
	defer server.Close()
	env := map[string]string{
		"GH_BROKER_AGENT_ENDPOINT": ghTestEndpoint(server.URL), "GH_BROKER_SHARED_SECRET": operationTestSecret,
		"GH_BROKER_MCP_EXACT_OPERATIONS": operation, "GH_BROKER_MCP_CLIENT_OPERATIONS": operation,
		"GH_BROKER_MCP_POLICY_OPERATIONS": operation, "GH_BROKER_MCP_RUNTIME_OPERATIONS": operation,
	}
	_, err := callGitHubMCP(t.Context(), mcpTestEnv(env), mcpserver.ToolCall{
		Name:      "gh_organization_update_webhook",
		Arguments: json.RawMessage(`{"target":{"kind":"organization","name":"osolmaz"},"arguments":{"hook_id":1},"reason":"leave unchanged","request_id":"optional-secret"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(submitted, []byte(`"arguments":{"public":{"hook_id":1}}`)) || bytes.Contains(submitted, []byte("sealed_payload")) {
		t.Fatalf("submitted = %s", submitted)
	}
}

func TestMCPCredentialOutputUsesNamedSlot(t *testing.T) {
	const operation = "runner.actions_create_registration_token_for_repo"
	var submitted []byte
	server := configureOperationTestClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/v1/operations" {
			t.Fatalf("unexpected route %s", request.URL.Path)
		}
		submitted, _ = io.ReadAll(request.Body)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(writer).Encode(githubTestOperation(agentv1.StatePending))
	}))
	defer server.Close()
	env := map[string]string{
		"GH_BROKER_AGENT_ENDPOINT": ghTestEndpoint(server.URL), "GH_BROKER_SHARED_SECRET": operationTestSecret,
		"GH_BROKER_MCP_EXACT_OPERATIONS": operation, "GH_BROKER_MCP_CLIENT_OPERATIONS": operation,
		"GH_BROKER_MCP_POLICY_OPERATIONS": operation, "GH_BROKER_MCP_RUNTIME_OPERATIONS": operation,
	}
	_, err := callGitHubMCP(t.Context(), mcpTestEnv(env), mcpserver.ToolCall{
		Name:      "gh_runner_actions_create_registration_token_for_repo",
		Arguments: json.RawMessage(`{"target":{"kind":"repo","owner":"osolmaz","name":"unyolo"},"arguments":{},"credential_slot":"ci-runner","reason":"enroll runner","request_id":"runner-token"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(submitted, []byte(`"credential_slot":"ci-runner"`)) || bytes.Contains(submitted, []byte(`"token"`)) {
		t.Fatalf("submitted = %s", submitted)
	}
}

func TestMCPRejectsUnsafeCallsAndResourceRequests(t *testing.T) {
	all := map[string]string{
		"GH_BROKER_MCP_EXACT_OPERATIONS":   "repo.metadata.read,agent_task.create_or_update_repo_secret",
		"GH_BROKER_MCP_CLIENT_OPERATIONS":  "repo.metadata.read,agent_task.create_or_update_repo_secret",
		"GH_BROKER_MCP_POLICY_OPERATIONS":  "repo.metadata.read,agent_task.create_or_update_repo_secret",
		"GH_BROKER_MCP_RUNTIME_OPERATIONS": "repo.metadata.read,agent_task.create_or_update_repo_secret",
	}
	for _, call := range []mcpserver.ToolCall{
		{Name: "gh_repo_metadata_read", Arguments: json.RawMessage(`{}`)},
		{Name: "gh_repo_metadata_read", Arguments: json.RawMessage(`{"target":{},"reason":"x","idempotency_key":"x","wait_seconds":901}`)},
		{Name: "gh_agent_task_create_or_update_repo_secret", Arguments: json.RawMessage(`{"reason":"x","idempotency_key":"x"}`)},
	} {
		if _, err := callGitHubMCP(t.Context(), mcpTestEnv(all), call); err == nil {
			t.Fatalf("accepted unsafe call %#v", call)
		}
	}
	for _, uri := range []string{
		"", "https://example.invalid", "github://operations?limit=bad", "github://operations?limit=101",
	} {
		if _, err := readMCPResource(uri); err == nil {
			t.Fatalf("accepted resource request %s", uri)
		}
	}
	result := mcpserver.ToolResult(map[string]any{"ok": true}, false)
	if result["isError"] != false || !strings.Contains(result["content"].([]map[string]any)[0]["text"].(string), "true") {
		t.Fatalf("result=%#v", result)
	}
}
