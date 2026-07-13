package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestCatalogSurfacesCoverEveryAgentFacingDescriptor(t *testing.T) {
	descriptors := agentFacingDescriptors()
	tools := catalogMCPTools()
	if len(descriptors) != 258 || len(tools) != len(descriptors) {
		t.Fatalf("descriptors=%d tools=%d", len(descriptors), len(tools))
	}
	for index, descriptor := range descriptors {
		words := strings.Fields(*descriptor.CLICommand)
		matched, consumed, found := matchCLICommand(append(words, "--json"))
		if !found || consumed != len(words) || matched.Name != descriptor.Name {
			t.Fatalf("CLI descriptor %q did not round trip", descriptor.Name)
		}
		if tools[index]["name"] != *descriptor.MCPTool {
			t.Fatalf("MCP descriptor %q drifted", descriptor.Name)
		}
		schema, ok := tools[index]["inputSchema"].(map[string]any)
		if !ok || schema["additionalProperties"] != false {
			t.Fatalf("MCP schema %q is not closed", descriptor.Name)
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
		if descriptor.AuthorizationMode == opcatalog.ModeExecution {
			assertClosedSchema(t, descriptor.Name+" arguments", properties["arguments"])
		} else {
			assertClosedSchema(t, descriptor.Name+" attrs", properties["attrs"])
		}
		if sealed, found := properties["sealed_arguments"]; found {
			assertClosedSchema(t, descriptor.Name+" sealed arguments", sealed)
		}
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
		`{"target":{"kind":"repo","type":"dataset","owner":"osolmaz","name":"throwaway"},"arguments":{},"reason":"remove test repository","idempotency_key":"delete-1","wait_seconds":0}`)})
	operation, ok := value.(agentv1.Operation)
	if err != nil || !ok || operation.Operation != "repo.delete" || submitted["operation"] != "repo.delete" {
		t.Fatalf("operation=%#v submitted=%#v err=%v", value, submitted, err)
	}
}

func TestMCPWindowOperationRequestsExactGrant(t *testing.T) {
	var submitted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/grants" || request.Method != http.MethodPost {
			t.Fatalf("request = %s %s", request.Method, request.URL.Path)
		}
		if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"success","data":{"grant":{"id":"grant-1","status":"pending","operation":"repo.contents.read","target":{"kind":"repo","type":"dataset","owner":"dutifuldev","name":"data"},"mode":"window","minutes":5,"max_uses":1,"uses_remaining":1,"used_count":0}}}`))
	}))
	defer server.Close()
	client, err := loadAgentClient(agentClientTestEnv(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	value, err := callMCPTool(t.Context(), client, mcpToolCall{Name: "hf_repo_contents_read", Arguments: json.RawMessage(
		`{"target":{"kind":"repo","type":"dataset","owner":"dutifuldev","name":"data"},"attrs":{},"reason":"inspect data","idempotency_key":"read-1","minutes":5,"max_uses":1,"wait_seconds":0}`)})
	grant, ok := value.(hfClientGrant)
	if err != nil || !ok || grant.Operation != "repo.contents.read" || submitted["operation"] != "repo.contents.read" {
		t.Fatalf("grant=%#v submitted=%#v err=%v", value, submitted, err)
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
			sealedBody = body.Bytes()
			writer.WriteHeader(http.StatusCreated)
			_, _ = writer.Write([]byte(`{"id":"sealed_abcdefghijklmnopqrstuvwx","owner":"agent","purpose":"space.secret.set","digest":"digest","size":40,"expires_at":9999999999}`))
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
		`{"target":{"namespace":"osolmaz","repo":"app"},"arguments":{"key":"TOKEN"},"sealed_arguments":{"value":"` + secret + `"},"reason":"set deployment secret","idempotency_key":"secret-1","wait_seconds":0}`)})
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
			operation := testAgentOperation(agentv1.StateSucceeded)
			operation.Operation = "repo.delete"
			_ = json.NewEncoder(writer).Encode(operation)
		case "/api/grants":
			_, _ = writer.Write([]byte(`{"status":"success","data":{"grant":{"id":"grant-1","status":"pending","operation":"repo.contents.read","target":{"kind":"repo","type":"dataset","owner":"dutifuldev","name":"data"},"mode":"window","minutes":5,"max_uses":1,"uses_remaining":1,"used_count":0}}}`))
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
		"--arguments-json", `{}`, "--idempotency-key", "delete-1", "--wait=false", "--json",
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
		"--attrs-json", `{}`, "--minutes", "5", "--max-uses", "1", "--idempotency-key", "read-1", "--wait=false", "--json",
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"operation":"repo.contents.read"`) {
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
