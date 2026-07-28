package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/mcp/grant"
	"github.com/osolmaz/unyolo/mcp/operation"
	"github.com/osolmaz/unyolo/protocol/contract"
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
		case "HF_BROKER_AGENT_ENDPOINT":
			return testTCPEndpoint(server.URL)
		case "HF_BROKER_SHARED_SECRET":
			return agentClientTestSecret
		default:
			return ""
		}
	}
	var stdout, stderr bytes.Buffer
	err := runAgentClient(context.Background(), getenv, &stdout, &stderr, []string{
		"repo", "create", "--target-json", `{"kind":"repo","type":"dataset","owner":"alice","name":"data"}`,
		"--arguments-json", `{"visibility":"private"}`, "--request-id", "create-data",
	})
	if err != nil {
		t.Fatal(err)
	}
	if eventCalls.Load() != 1 || !strings.Contains(stdout.String(), "alice/data") || !strings.Contains(stderr.String(), "Approval requested") {
		t.Fatalf("stdout=%q stderr=%q calls=%d", stdout.String(), stderr.String(), eventCalls.Load())
	}
}

func TestRunAgentClientGrantLifecycle(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+agentClientTestSecret {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		status := "pending"
		if request.Method == http.MethodPost && request.URL.Path == "/api/grants" {
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if value, exists := body["max_uses"]; !exists || value != nil {
				t.Fatalf("max_uses = %#v, exists=%v", value, exists)
			}
		} else if strings.HasSuffix(request.URL.Path, "/cancel") {
			status = "canceled"
		} else if strings.HasSuffix(request.URL.Path, "/revoke") {
			status = "revoked"
		} else {
			status = "active"
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"status": "success",
			"data": map[string]any{"grant": map[string]any{
				"id": "grant-1", "status": status, "operation": "git.push.force",
				"target": map[string]any{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"},
				"attrs":  map[string]any{},
				"mode":   "window", "minutes": 5, "max_uses": nil, "uses_remaining": 0, "used_count": 0,
			}},
		})
	}))
	defer server.Close()
	env := agentClientTestEnv(server.URL)
	var stdout bytes.Buffer
	if err := runClientCommand(t.Context(), env, &stdout, &bytes.Buffer{}, []string{
		"grant", "request", "git.push.force", "acme/repo", "--ref", "refs/heads/main",
		"--max-uses", "unlimited", "--request-id", "request-1", "--json",
	}); err != nil || !strings.Contains(stdout.String(), `"max_uses":null`) {
		t.Fatalf("grant request = %q, %v", stdout.String(), err)
	}
	for _, action := range []string{"get", "wait", "cancel", "revoke"} {
		stdout.Reset()
		if err := runGrantClientFromEnv(t.Context(), env, &stdout, &bytes.Buffer{}, []string{action, "--json", "grant-1"}); err != nil {
			t.Fatalf("grant %s error = %v", action, err)
		}
	}
	mcpClient, err := loadAgentClient(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hf_grant_get", "hf_grant_wait", "hf_grant_cancel", "hf_grant_revoke"} {
		arguments := `{"grant_id":"grant-1"}`
		if name == "hf_grant_wait" {
			arguments = `{"grant_id":"grant-1","wait_seconds":1}`
		}
		value, err := callMCPTool(t.Context(), mcpClient, mcpToolCall{
			Name: name, Arguments: json.RawMessage(arguments),
		})
		if grant, ok := value.(mcpgrant.Grant); err != nil || !ok || grant.ID != "grant-1" || grant.APIVersion != mcpgrant.APIVersion {
			t.Fatalf("%s = %#v, %v", name, value, err)
		}
	}
	if _, err := callMCPTool(t.Context(), mcpClient, mcpToolCall{
		Name: "hf_grant_get", Arguments: json.RawMessage(`{"grant_id":"grant-1","wait_seconds":1}`),
	}); err == nil {
		t.Fatal("hf_grant_get accepted wait_seconds")
	}
	if _, err := callMCPTool(t.Context(), mcpClient, mcpToolCall{
		Name: "hf_grant_wait", Arguments: json.RawMessage(`{"grant_id":"grant-1","wait_seconds":26}`),
	}); err == nil {
		t.Fatal("hf_grant_wait accepted a wait above the bounded MCP deadline")
	}
	waitProperties := mcpIDSchema("grant_id", true)["properties"].(map[string]any)
	waitSchema := waitProperties["wait_seconds"].(map[string]any)
	if waitSchema["maximum"] != mcpoperation.MaxWaitSeconds {
		t.Fatalf("hf_grant_wait maximum = %v", waitSchema["maximum"])
	}
	if err := runGrantClientFromEnv(t.Context(), env, &stdout, &bytes.Buffer{}, []string{"request", "missing", "bad"}); err == nil {
		t.Fatal("invalid grant request succeeded")
	}
	if err := runClientCommand(t.Context(), env, &stdout, &bytes.Buffer{}, []string{"unknown"}); err == nil {
		t.Fatal("unknown client command succeeded")
	}
}

func TestGrantRequestOptionValidation(t *testing.T) {
	t.Parallel()
	valid := grantRequestOptions{
		operation: "git.push.force", target: "acme/repo", repoType: "dataset",
		reason: "repair", waitTimeout: time.Minute,
	}
	for _, mutate := range []func(*grantRequestOptions){
		func(value *grantRequestOptions) { value.repoType = "invalid" },
		func(value *grantRequestOptions) { value.minutes = -1 },
		func(value *grantRequestOptions) { value.operation = "missing" },
	} {
		candidate := valid
		mutate(&candidate)
		if err := validateGrantRequestOptions(candidate); err == nil {
			t.Fatalf("validateGrantRequestOptions(%+v) succeeded", candidate)
		}
	}
	badTarget := valid
	badTarget.target = "invalid"
	if _, err := buildHFGrantRequest(&badTarget); err == nil {
		t.Fatal("buildHFGrantRequest accepted invalid target")
	}
	omitted := valid
	omitted.idempotencyKey = "omitted"
	request, err := buildHFGrantRequest(&omitted)
	if err != nil || request.MaxUses != nil {
		t.Fatalf("omitted max uses = %+v, %v", request.MaxUses, err)
	}
	finite := valid
	finite.idempotencyKey = "finite"
	if err := finite.maxUses.Set("3"); err != nil {
		t.Fatal(err)
	}
	request, err = buildHFGrantRequest(&finite)
	if err != nil || request.MaxUses == nil || *request.MaxUses != 3 {
		t.Fatalf("finite max uses = %+v, %v", request.MaxUses, err)
	}
	if err := finite.maxUses.Set("zero"); err == nil {
		t.Fatal("invalid max uses succeeded")
	}
	bucket := grantRequestOptions{
		operation: "bucket.object.write", target: "acme/artifacts", keys: stringListFlag{"runs/**"},
		reason: "publish artifacts", waitTimeout: time.Minute, idempotencyKey: "bucket-write",
	}
	if err := validateGrantRequestOptions(bucket); err != nil {
		t.Fatalf("bucket grant options rejected: %v", err)
	}
	request, err = buildHFGrantRequest(&bucket)
	if err != nil || request.Target.Kind != "bucket" || !slices.Equal(request.Target.Keys, []string{"runs/**"}) {
		t.Fatalf("bucket grant request = %+v, %v", request, err)
	}
	bucket.refs = stringListFlag{"refs/heads/main"}
	if err := validateGrantRequestOptions(bucket); err == nil {
		t.Fatal("bucket grant accepted repository ref scope")
	}
	if err := validateGrantTargetOptions(opcatalog.Descriptor{TargetKind: string(policy.KindInference)}, grantRequestOptions{}); err == nil {
		t.Fatal("grant target options accepted unsupported target kind")
	}
}

func TestValidateGrantTargetOptions(t *testing.T) {
	t.Parallel()
	repo := opcatalog.Descriptor{TargetKind: string(policy.KindRepo)}
	bucket := opcatalog.Descriptor{TargetKind: string(policy.KindBucket)}
	tests := []struct {
		name       string
		descriptor opcatalog.Descriptor
		options    grantRequestOptions
		wantError  bool
	}{
		{name: "repository", descriptor: repo, options: grantRequestOptions{repoType: "dataset"}},
		{name: "repository type", descriptor: repo, options: grantRequestOptions{repoType: "kernel"}, wantError: true},
		{name: "repository key", descriptor: repo, options: grantRequestOptions{repoType: "dataset", keys: stringListFlag{"key"}}, wantError: true},
		{name: "bucket", descriptor: bucket},
		{name: "bucket ref", descriptor: bucket, options: grantRequestOptions{refs: stringListFlag{"main"}}, wantError: true},
		{name: "unsupported", descriptor: opcatalog.Descriptor{TargetKind: string(policy.KindInference)}, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateGrantTargetOptions(test.descriptor, test.options)
			if (err != nil) != test.wantError {
				t.Fatalf("validateGrantTargetOptions() error = %v, wantError %v", err, test.wantError)
			}
		})
	}
}

func TestDecodeMCPGrantRequestPreservesUnlimitedScopedWrite(t *testing.T) {
	t.Parallel()
	input, err := decodeMCPGrantRequest(json.RawMessage(`{
		"operation":"bucket.object.write",
		"target":{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/**"]},
		"minutes":10080,"max_uses":null,"reason":"publish artifacts","request_id":"bucket-week"
	}`))
	if err != nil {
		t.Fatalf("decodeMCPGrantRequest() error = %v", err)
	}
	if !input.MaxUses.Specified || !input.MaxUses.Limit.IsUnlimited() || input.Minutes != 10080 || !slices.Equal(input.Target.Keys, []string{"runs/**"}) {
		t.Fatalf("input = %+v", input)
	}
}

func TestCallMCPGrantRequestProjectsActiveGrant(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/grants" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"grant": hfClientGrant{
			ID: "grant-1", Status: "active", Operation: "bucket.object.write", Mode: policy.GrantModeWindow,
			Target: policy.Target{Kind: policy.KindBucket, Owner: "acme", Name: "artifacts", Keys: []string{"runs/**"}},
			Attrs:  map[string]any{}, Minutes: 10080, MaxUses: 0, UsesRemaining: -1, ClientRequestID: "bucket-week",
		}}})
	}))
	defer server.Close()
	client, err := newHFGrantClient("tcp://"+strings.TrimPrefix(server.URL, "http://"), strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := callMCPGrantRequest(t.Context(), client, json.RawMessage(`{
		"operation":"bucket.object.write",
		"target":{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/**"]},
		"attrs":{},"minutes":10080,"max_uses":null,"reason":"publish artifacts","request_id":"bucket-week"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if grant.ID != "grant-1" || grant.Status != "active" || grant.RequestID != "bucket-week" || grant.UsesRemaining != -1 {
		t.Fatalf("grant = %+v", grant)
	}
}

func TestCallMCPGrantRequestWaitsByDefault(t *testing.T) {
	t.Parallel()
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status := "pending"
		if r.Method == http.MethodGet {
			reads.Add(1)
			status = "active"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "success", "data": map[string]any{"grant": hfClientGrant{
			ID: "grant-pending", Status: status, Operation: "bucket.object.write", Mode: policy.GrantModeWindow,
			Target: policy.Target{Kind: policy.KindBucket, Owner: "acme", Name: "artifacts", Keys: []string{"runs/**"}},
			Attrs:  map[string]any{}, Minutes: 5, MaxUses: 1, ClientRequestID: "bucket-pending",
		}}})
	}))
	defer server.Close()
	client, err := newHFGrantClient("tcp://"+strings.TrimPrefix(server.URL, "http://"), strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := callMCPGrantRequest(t.Context(), client, json.RawMessage(`{
		"operation":"bucket.object.write",
		"target":{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/**"]},
		"attrs":{},"minutes":5,"max_uses":1,"reason":"publish artifacts","request_id":"bucket-pending"
	}`))
	if err != nil || grant.ID != "grant-pending" || grant.Status != "active" || reads.Load() == 0 {
		t.Fatalf("grant = %+v, reads = %d, error = %v", grant, reads.Load(), err)
	}
}

func TestBucketObjectWriteCLIUploadsAndBindsLocalSource(t *testing.T) {
	t.Parallel()
	var submitted agentv1.SubmitRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/v1/streams":
			body, _ := io.ReadAll(r.Body)
			if string(body) != "artifact" || r.Header.Get("X-Broker-Operation") != "bucket.object.write" || r.Header.Get("X-Broker-Idempotency-Key") != "write-1" {
				t.Fatalf("stream request = %q headers=%v", body, r.Header)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(agentv1.StreamReference{ID: "stream_012345678901234567890123", Owner: "agent", Purpose: "bucket.object.write",
				TransferID: "write-1", Digest: strings.Repeat("a", 64), Size: 8, MediaType: "application/octet-stream", ExpiresAt: time.Now().Add(time.Hour).Unix()})
		case "/api/agent/v1/operations":
			if err := json.NewDecoder(r.Body).Decode(&submitted); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(testAgentOperation(agentv1.StatePending))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, _ := opcatalog.ByName("bucket.object.write")
	source := filepath.Join(t.TempDir(), "artifact.bin")
	if err := os.WriteFile(source, []byte("artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	err = runCatalogOperation(t.Context(), client, &stdout, &bytes.Buffer{}, descriptor, []string{
		"--target-json", `{"kind":"bucket","namespace":"acme","name":"artifacts"}`,
		"--arguments-json", `{"path":"runs/artifact.bin"}`, "--source", source,
		"--request-id", "write-1", "--wait=false", "--json",
	})
	if err != nil {
		t.Fatal(err)
	}
	arguments := string(submitted.Arguments)
	if submitted.Operation != "bucket.object.write" || !strings.Contains(arguments, `"transfer_id":"write-1"`) || strings.Contains(arguments, "request_key") || strings.Contains(arguments, `"content"`) {
		t.Fatalf("submitted = %+v", submitted)
	}
}

func TestRunMCPListsAndCallsTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/unyolo-agent" {
			_ = json.NewEncoder(w).Encode(agentv1.Descriptor{APIVersion: agentv1.APIVersion,
				ContractDigest: contract.AgentV1Digest, BuildID: "test", Operations: []string{"repo.create"},
				Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "huggingface", CredentialKind: "fine_grained_user_token", Generation: 1, VerificationState: "valid"}})
			return
		}
		_ = json.NewEncoder(w).Encode(testAgentOperation(agentv1.StatePending))
	}))
	defer server.Close()
	getenv := func(name string) string {
		if name == "HF_BROKER_AGENT_ENDPOINT" {
			return testTCPEndpoint(server.URL)
		}
		if name == "HF_BROKER_SHARED_SECRET" {
			return agentClientTestSecret
		}
		return ""
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"hf_repo_create","arguments":{"target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"create","request_id":"one"}}}`,
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

func TestMCPToolsDoNotTreatEmptyDiscoveryAsFullAccess(t *testing.T) {
	tools := mcpTools([]string{})
	if len(tools) != 5 {
		t.Fatalf("empty discovery tools = %d, want only five grant utilities", len(tools))
	}
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if !strings.HasPrefix(name, "hf_grant_") {
			t.Fatalf("empty discovery exposed operation tool %q", name)
		}
	}
}

func TestMCPToolsAdvertiseLifecycleForAvailableOperations(t *testing.T) {
	tools := mcpTools([]string{"repo.create"})
	names := make(map[string]bool, len(tools))
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		names[name] = true
	}
	for _, name := range []string{
		"hf_repo_create", "hf_operation_get", "hf_operation_wait", "hf_operation_list", "hf_operation_cancel",
	} {
		if !names[name] {
			t.Fatalf("available operation tools omit %q: %v", name, names)
		}
	}
	if names["hf_repo_delete"] {
		t.Fatalf("discovery exposed unavailable repository deletion: %v", names)
	}
}

func TestLoadAgentClientRejectsMissingCredential(t *testing.T) {
	_, err := loadAgentClient(func(name string) string {
		if name == "HF_BROKER_AGENT_ENDPOINT" {
			return "tcp://127.0.0.1:32191"
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
		case "HF_BROKER_AGENT_ENDPOINT":
			return "tcp://127.0.0.1:32191"
		case "HF_BROKER_SHARED_SECRET_FILE":
			return secretFile
		default:
			return ""
		}
	})
	if err != nil || client.operations == nil || client.grantClient == nil {
		t.Fatalf("file client = %#v, %v", client, err)
	}
	for _, value := range []string{"", "ftp://example.test", "tcp://localhost:1", "tcp://127.0.0.1:1?x=1"} {
		if _, err := loadAgentClient(func(name string) string {
			if name == "HF_BROKER_AGENT_ENDPOINT" {
				return value
			}
			if name == "HF_BROKER_SHARED_SECRET" {
				return agentClientTestSecret
			}
			return ""
		}); err == nil {
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
}

func TestCatalogOperationOptionsAndTerminalOutput(t *testing.T) {
	descriptor, _, found := matchCLICommand([]string{"repo", "create"})
	if !found || descriptor.Name != "repo.create" {
		t.Fatalf("repo create descriptor = %#v, %v", descriptor, found)
	}
	for _, args := range [][]string{
		{},
		{"--target-json", `{}`, "--reason", ""},
		{"--target-json", `{}`, "--sealed-file", "secret.json"},
		{"--target-json", `{}`, "extra"},
	} {
		if _, err := parseOperationClientOptions(descriptor, args); err == nil {
			t.Fatalf("options accepted: %v", args)
		}
	}
	options, err := parseOperationClientOptions(descriptor, []string{
		"--target-json", `{"kind":"repo","type":"dataset","owner":"alice","name":"data"}`,
		"--arguments-json", `{"visibility":"private"}`, "--request-id", "create-data",
	})
	if err != nil || options.idempotencyKey != "create-data" {
		t.Fatalf("catalog options = %#v, %v", options, err)
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
		if r.URL.Path == "/.well-known/unyolo-agent" {
			_ = json.NewEncoder(w).Encode(agentv1.Descriptor{APIVersion: agentv1.APIVersion,
				ContractDigest: contract.AgentV1Digest, BuildID: "test", Operations: []string{"repo.create"},
				Credential: agentv1.CredentialDescriptor{Ready: true, Provider: "huggingface", CredentialKind: "token", Generation: 1, VerificationState: "valid"}})
			return
		}
		operation := testAgentOperation(agentv1.StateSucceeded)
		_ = json.NewEncoder(w).Encode(operation)
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hf_operation_get", "hf_operation_wait", "hf_operation_cancel"} {
		value, err := callMCPTool(context.Background(), client, mcpToolCall{Name: name, Arguments: json.RawMessage(`{"operation_id":"op_test"}`)})
		operation, ok := value.(mcpoperation.Operation)
		if err != nil || !ok || operation.ID != "op_test" {
			t.Fatalf("%s = %#v, %v", name, value, err)
		}
	}
	if _, err := callMCPTool(context.Background(), client, mcpToolCall{Name: "unknown", Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("unknown MCP tool accepted")
	}
	if _, err := callMCPTool(context.Background(), client, mcpToolCall{Name: "hf_repo_create", Arguments: json.RawMessage(`{"target":{},"arguments":{},"reason":"create","idempotency_key":"bad-wait","wait_seconds":901}`)}); err == nil {
		t.Fatal("oversized repository wait accepted")
	}
	tools := catalogMCPTools()
	if len(tools) != len(agentFacingDescriptors())+4 {
		t.Fatalf("catalog MCP tools = %d", len(tools))
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
	for _, call := range []mcpToolCall{
		{Name: "hf_operation_wait", Arguments: json.RawMessage(`{"operation_id":"op_test","timeout_seconds":1}`)},
		{Name: "hf_repo_create", Arguments: json.RawMessage(`{"target":{"kind":"repo","type":"dataset","owner":"alice","name":"data"},"arguments":{"visibility":"private"},"reason":"create","request_id":"create"}`)},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		value, callErr := callMCPTool(ctx, client, call)
		cancel()
		operation, ok := value.(mcpoperation.Operation)
		if callErr != nil || !ok || operation.ID != "op_test" || operation.State != agentv1.StatePending {
			t.Fatalf("%s = %#v, %v", call.Name, value, callErr)
		}
	}
}

func agentClientTestEnv(serverURL string) func(string) string {
	return func(name string) string {
		if name == "HF_BROKER_AGENT_ENDPOINT" {
			return testTCPEndpoint(serverURL)
		}
		if name == "HF_BROKER_SHARED_SECRET" {
			return agentClientTestSecret
		}
		return ""
	}
}

func testTCPEndpoint(serverURL string) string {
	return strings.Replace(serverURL, "http://", "tcp://", 1)
}

func testAgentOperation(state agentv1.State) agentv1.Operation {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	return agentv1.Operation{APIVersion: agentv1.APIVersion, ID: "op_test", Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "one",
		Operation: "repo.create", Target: json.RawMessage(`{"kind":"repo"}`), Arguments: json.RawMessage(`{"visibility":"private"}`), State: state,
		Revision: 2, CreatedAt: now, UpdatedAt: now, Presentation: agentv1.Presentation{Title: "Create", Summary: "Create alice/data"}}
}
