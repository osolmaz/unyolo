package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/mcpprojection"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opbinding"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/capability"
	"github.com/osolmaz/brokerkit/mcpoperation"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestCatalogSurfacesCoverEveryAgentFacingDescriptor(t *testing.T) {
	descriptors := agentFacingDescriptors()
	if len(descriptors) != 144 {
		t.Fatalf("descriptors=%d", len(descriptors))
	}
	for _, descriptor := range descriptors {
		descriptor := descriptor
		t.Run(descriptor.Name, func(t *testing.T) {
			words := strings.Fields(*descriptor.CLICommand)
			matched, consumed, found := matchCLICommand(append(words, "--json"))
			if !found || consumed != len(words) || matched.Name != descriptor.Name {
				t.Fatalf("CLI descriptor %q did not round trip", descriptor.Name)
			}
			schema := catalogMCPToolSchemaForTest(t, descriptor)
			if schema == nil {
				return
			}
			if schema["additionalProperties"] != false {
				t.Fatalf("MCP schema %q is not closed", descriptor.Name)
			}
			if issues := capability.AuditMCPToolSchema(schema); len(issues) != 0 {
				t.Fatalf("MCP schema %q has unresolved compatibility issue: %v", descriptor.Name, issues[0])
			}
			compiler := jsonschema.NewCompiler()
			compiler.UseRegexpEngine(compileMCPTestRegexp)
			location := "https://brokerkit.local/mcp/" + descriptor.Name + ".json"
			encoded, _ := json.Marshal(schema)
			var normalized any
			_ = json.Unmarshal(encoded, &normalized)
			if err := compiler.AddResource(location, normalized); err != nil {
				t.Fatalf("MCP schema %q could not be loaded: %v", descriptor.Name, err)
			}
			if _, err := compiler.Compile(location); err != nil {
				t.Fatalf("MCP schema %q could not be compiled: %v", descriptor.Name, err)
			}
			properties := schema["properties"].(map[string]any)
			assertClosedSchema(t, descriptor.Name+" target", properties["target"])
			assertClosedSchema(t, descriptor.Name+" arguments", properties["arguments"])
			if sealed, found := properties["sealed_arguments"]; found {
				assertClosedSchema(t, descriptor.Name+" sealed arguments", sealed)
			}
		})
	}
	if t.Failed() {
		return
	}
	tools := catalogMCPTools()
	if len(tools) != len(descriptors)+4 {
		t.Fatalf("descriptors=%d tools=%d", len(descriptors), len(tools))
	}
}

func catalogMCPToolSchemaForTest(t *testing.T, descriptor opcatalog.Descriptor) (schema map[string]any) {
	t.Helper()
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("MCP schema generation panicked: %v", value)
			schema = nil
		}
	}()
	return catalogMCPToolSchema(descriptor)
}

func TestCapturedResultsAreTranscriptSafe(t *testing.T) {
	for _, descriptor := range agentFacingDescriptors() {
		binding, found := opbinding.ByName(descriptor.Name)
		if !found || !binding.CaptureResult {
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(binding.ResultSchema, &schema); err != nil {
			t.Fatalf("%s result schema: %v", descriptor.Name, err)
		}
		projection := mcpprojection.ForOperation(descriptor).Result
		if !projection.Empty() {
			var err error
			schema, err = projection.MCPSchema(schema)
			if err != nil {
				t.Fatalf("%s result projection: %v", descriptor.Name, err)
			}
		}
		if issues := capability.AuditMCPPublicSchema(schema); len(issues) != 0 {
			t.Fatalf("%s result schema has unresolved compatibility issue: %v", descriptor.Name, issues[0])
		}
	}
}

func TestMCPCompatibilityManifestMatchesCatalog(t *testing.T) {
	raw, err := os.ReadFile("../../docs/generated/mcp-compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		APIVersion                string   `json:"api_version"`
		Provider                  string   `json:"provider"`
		HostProfiles              []string `json:"host_profiles"`
		AgentFacingOperations     int      `json:"agent_facing_operations"`
		OperationTools            int      `json:"operation_tools"`
		UtilityTools              int      `json:"utility_tools"`
		ProjectedOperations       []string `json:"projected_operations"`
		ProjectedWindowOperations int      `json:"projected_window_operations"`
		UnresolvedCollisions      int      `json:"unresolved_collisions"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	projected, windows := []string{}, 0
	for _, descriptor := range agentFacingDescriptors() {
		projection := mcpprojection.ForOperation(descriptor)
		if descriptor.AuthorizationMode == opcatalog.ModeWindow {
			windows++
		}
		if !projection.Arguments.Empty() {
			projected = append(projected, descriptor.Name)
		}
	}
	if manifest.APIVersion != "brokerkit.io/mcp-compatibility-manifest/v1" || manifest.Provider != "huggingface" ||
		!slices.Equal(manifest.HostProfiles, []string{"openclaw@2026.7.1"}) ||
		manifest.AgentFacingOperations != len(agentFacingDescriptors()) || manifest.OperationTools != len(agentFacingDescriptors()) ||
		manifest.UtilityTools != 4 || !slices.Equal(manifest.ProjectedOperations, projected) ||
		manifest.ProjectedWindowOperations != windows || manifest.UnresolvedCollisions != 0 {
		t.Fatalf("compatibility manifest drifted: %+v", manifest)
	}
}

type mcpTestRegexp regexp2.Regexp

func (regexp *mcpTestRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(regexp).MatchString(value)
	return err == nil && matched
}

func (regexp *mcpTestRegexp) String() string { return (*regexp2.Regexp)(regexp).String() }

func compileMCPTestRegexp(pattern string) (jsonschema.Regexp, error) {
	compiled, err := regexp2.Compile(pattern, regexp2.ECMAScript)
	return (*mcpTestRegexp)(compiled), err
}

func TestCatalogSchemasSeparateProtectedArguments(t *testing.T) {
	for _, operation := range []string{"space.secret.set", "endpoint.create", "sandbox.create"} {
		descriptor, _ := opcatalog.ByName(operation)
		properties := catalogMCPToolSchema(descriptor)["properties"].(map[string]any)
		if properties["sealed_arguments"] == nil {
			t.Fatalf("%s has no sealed argument schema", operation)
		}
	}

	space, _ := opcatalog.ByName("space.secret.set")
	spaceProperties := catalogMCPToolSchema(space)["properties"].(map[string]any)
	public := spaceProperties["arguments"].(map[string]any)["properties"].(map[string]any)
	sealed := spaceProperties["sealed_arguments"].(map[string]any)["properties"].(map[string]any)
	if public["value"] != nil || sealed["value"] == nil {
		t.Fatalf("space.secret.set schemas expose the protected value: public=%#v sealed=%#v", public, sealed)
	}

	pool, _ := opcatalog.ByName("sandbox.pool.create")
	poolProperties := catalogMCPToolSchema(pool)["properties"].(map[string]any)
	if pool.Sealed || poolProperties["sealed_arguments"] != nil {
		t.Fatalf("sandbox.pool.create advertises unsupported secret input: %#v", poolProperties)
	}
}

func assertClosedSchema(t *testing.T, name string, value any) {
	t.Helper()
	switch schema := value.(type) {
	case map[string]any:
		if schema["type"] == "object" {
			_, bounded := schema["additionalProperties"]
			if !bounded && schema["maxProperties"] != float64(0) && schema["maxProperties"] != 0 {
				t.Fatalf("%s contains an open object schema: %#v", name, schema)
			}
		}
		for key, nested := range schema {
			assertClosedSchema(t, name+"."+key, nested)
		}
	case []any:
		for index, nested := range schema {
			assertClosedSchema(t, fmt.Sprintf("%s[%d]", name, index), nested)
		}
	}
}

func TestMCPDestructiveOperationUsesCatalogOperation(t *testing.T) {
	var submitted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/v1/operations" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
			t.Fatal(err)
		}
		operation := testAgentOperation(agentv1.StatePending)
		operation.Operation = "repo.delete"
		_ = json.NewEncoder(writer).Encode(operation)
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	value, err := callMCPTool(t.Context(), client, mcpToolCall{Name: "hf_repo_delete", Arguments: json.RawMessage(
		`{"target":{"kind":"repo","type":"dataset","owner":"osolmaz","name":"throwaway"},"arguments":{},"reason":"remove test repository","request_id":"delete-1"}`)})
	operation, ok := value.(mcpoperation.Operation)
	if err != nil || !ok || operation.Operation != "repo.delete" || submitted["operation"] != "repo.delete" {
		t.Fatalf("operation=%#v submitted=%#v err=%v", value, submitted, err)
	}
}

func TestSubmitWaitTimeoutReturnsResumableOperation(t *testing.T) {
	pending := testAgentOperation(agentv1.StatePending)
	updated := pending
	updated.Revision++
	updated.Presentation.Summary = "approval requested"
	var waits int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/api/agent/v1/operations":
			writer.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(writer).Encode(pending)
		case request.Method == http.MethodGet && strings.Contains(request.URL.Path, "/api/agent/v1/operations/"):
			waits++
			if waits == 1 {
				_ = json.NewEncoder(writer).Encode(updated)
				return
			}
			<-request.Context().Done()
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	operation, err := submitAndMaybeWait(t.Context(), client, agentv1.SubmitRequest{
		IdempotencyKey: "timeout-1", Operation: "repo.delete", Target: json.RawMessage(`{"kind":"repo"}`),
		Arguments: json.RawMessage(`{}`), Reason: "test resumable timeout",
	}, true, 10*time.Millisecond)
	if err != nil || operation.ID != pending.ID || operation.State != agentv1.StatePending || operation.Revision != updated.Revision || operation.Presentation.Summary != updated.Presentation.Summary {
		t.Fatalf("timed wait = %+v, %v", operation, err)
	}
}

func TestMCPWindowOperationSubmitsAgentOperation(t *testing.T) {
	var submitted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/v1/operations" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		operation := testAgentOperation(agentv1.StatePending)
		operation.Operation = "repo.contents.read"
		_ = json.NewEncoder(writer).Encode(operation)
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	value, err := callMCPTool(t.Context(), client, mcpToolCall{Name: "hf_repo_contents_read", Arguments: json.RawMessage(
		`{"target":{"kind":"repo","type":"dataset","owner":"dutifuldev","name":"data"},"arguments":{"path":"README.md"},"reason":"inspect data","request_id":"read-1"}`)})
	operation, ok := value.(mcpoperation.Operation)
	if err != nil || !ok || operation.Operation != "repo.contents.read" || submitted["operation"] != "repo.contents.read" {
		t.Fatalf("operation=%#v submitted=%#v err=%v", value, submitted, err)
	}
}

func TestMCPSealedOperationSeparatesSecretFromPlan(t *testing.T) {
	const secret = "not-in-the-operation-plan"
	var sealedBody, operationBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(request.Body)
		switch request.URL.Path {
		case "/api/agent/v1/sealed-payloads":
			if request.Header.Get("X-Broker-Idempotency-Key") != "secret-1" {
				t.Fatalf("sealed idempotency key = %q", request.Header.Get("X-Broker-Idempotency-Key"))
			}
			sealedBody = body.Bytes()
			digest := sha256.Sum256(sealedBody)
			writer.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(writer, `{"id":"sealed_abcdefghijklmnopqrstuvwx","owner":"agent","purpose":"space.secret.set","request_key":"secret-1","digest":%q,"size":%d,"expires_at":9999999999}`,
				hex.EncodeToString(digest[:]), len(sealedBody))
		case "/api/agent/v1/operations":
			operationBody = body.Bytes()
			operation := testAgentOperation(agentv1.StatePending)
			operation.Operation = "space.secret.set"
			_ = json.NewEncoder(writer).Encode(operation)
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, err = callMCPTool(context.Background(), client, mcpToolCall{Name: "hf_space_secret_set", Arguments: json.RawMessage(
		`{"target":{"namespace":"osolmaz","repo":"app"},"arguments":{"secret_name":"TOKEN"},"sealed_arguments":{"value":"` + secret + `"},"reason":"set deployment secret","request_id":"secret-1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(sealedBody, []byte(secret)) || bytes.Contains(operationBody, []byte(secret)) || !bytes.Contains(operationBody, []byte("sealed_abcdefghijklmnopqrstuvwx")) {
		t.Fatalf("sealed=%q operation=%q", sealedBody, operationBody)
	}
}

func TestCatalogSchemaUsesPinnedBindingWhenAvailable(t *testing.T) {
	descriptor, found := opcatalog.ByName("space.secret.set")
	if !found {
		t.Fatal("space.secret.set missing")
	}
	schema := catalogMCPToolSchema(descriptor)
	properties := schema["properties"].(map[string]any)
	arguments := properties["arguments"].(map[string]any)
	if arguments["type"] != "object" || properties["sealed_arguments"] == nil {
		t.Fatalf("schema = %#v", schema)
	}
	if !slices.Contains(schema["required"].([]string), "sealed_arguments") {
		t.Fatalf("mandatory sealed arguments are optional: %#v", schema)
	}
	sealed := properties["sealed_arguments"].(map[string]any)
	if !slices.Contains(requiredPropertyNames(sealed), "value") {
		t.Fatalf("sealed value is optional: %#v", sealed)
	}
}

func TestCatalogSchemaUsesCustomAndNativeProtocolTargets(t *testing.T) {
	read, found := opcatalog.ByName("repo.contents.read")
	if !found {
		t.Fatal("repo.contents.read missing")
	}
	target, arguments, _ := catalogOperationInputSchemas(read)
	if target == nil || arguments == nil {
		t.Fatal("custom repository schema missing")
	}
	native, found := opcatalog.ByName("git.push.force")
	if !found {
		t.Fatal("git.push.force missing")
	}
	target, arguments, sealed := catalogOperationInputSchemas(native)
	if target == nil || arguments != nil || sealed != nil {
		t.Fatalf("native protocol schema = %#v, %#v, %#v", target, arguments, sealed)
	}
}

func TestCredentialOutputToolRequiresSlotAndHidesSealedInput(t *testing.T) {
	descriptor, found := opcatalog.ByName("service_account.token.create")
	if !found || descriptor.CredentialOutputKind == nil {
		t.Fatal("credential output metadata missing")
	}
	schema := catalogMCPToolSchema(descriptor)
	properties := schema["properties"].(map[string]any)
	if properties["credential_slot"] == nil || properties["sealed_arguments"] != nil {
		t.Fatalf("credential output schema = %#v", schema)
	}
	required := schema["required"].([]string)
	if !slices.Contains(required, "credential_slot") {
		t.Fatalf("required = %v", required)
	}
}

func TestCatalogCLIExecutionAndWindowOperations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/api/agent/v1/operations":
			var submitted struct {
				Operation string `json:"operation"`
			}
			_ = json.NewDecoder(request.Body).Decode(&submitted)
			operation := testAgentOperation(agentv1.StateSucceeded)
			operation.Operation = submitted.Operation
			_ = json.NewEncoder(writer).Encode(operation)
		default:
			t.Fatalf("unexpected CLI request: %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	deleteDescriptor, _ := opcatalog.ByName("repo.delete")
	if err := runCatalogOperation(t.Context(), client, &stdout, &stderr, deleteDescriptor, []string{
		"--target-json", `{"kind":"repo","type":"dataset","owner":"osolmaz","name":"throwaway"}`,
		"--arguments-json", `{}`, "--request-id", "delete-1", "--wait=false", "--json",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"operation": "repo.delete"`) {
		t.Fatalf("execution output = %q", stdout.String())
	}
	stdout.Reset()
	readDescriptor, _ := opcatalog.ByName("repo.contents.read")
	if err := runCatalogOperation(t.Context(), client, &stdout, &stderr, readDescriptor, []string{
		"--target-json", `{"kind":"repo","type":"dataset","owner":"dutifuldev","name":"data"}`,
		"--arguments-json", `{"path":"README.md"}`, "--request-id", "read-1", "--wait=false", "--json",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"operation": "repo.contents.read"`) {
		t.Fatalf("window output = %q", stdout.String())
	}
}

func TestCatalogCLIReadsBoundedJSONFilesAndRejectsMixedInputs(t *testing.T) {
	path := t.TempDir() + "/target.json"
	if err := os.WriteFile(path, []byte(`{"kind":"repo","type":"dataset","owner":"osolmaz","name":"throwaway"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, _ := opcatalog.ByName("repo.delete")
	options, err := parseOperationClientOptions(descriptor, []string{"--target-file", path, "--arguments-json", `{}`, "--wait=false"})
	if err != nil || !bytes.Contains(options.target, []byte("throwaway")) {
		t.Fatalf("options = %+v, %v", options, err)
	}
	if _, err := readJSONOption(`{}`, path, true); err == nil {
		t.Fatal("mixed inline and file JSON accepted")
	}
	if _, err := readJSONOption("", "", true); err == nil {
		t.Fatal("missing required JSON accepted")
	}
}
