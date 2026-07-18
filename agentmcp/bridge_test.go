package agentmcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/mcpserver"
)

const testSecret = "01234567890123456789012345678901"

func TestBridgeSubmitsEverySelectedOperation(t *testing.T) {
	var submitted map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/agent/v1/operations" {
			http.NotFound(writer, request)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&submitted); err != nil {
			t.Fatal(err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"api_version":"brokerkit.io/agent/v1","id":"op_1","broker":"test","client_id":"agent","idempotency_key":"req_1","operation":"repo.read","target":{"kind":"repo"},"arguments":{},"reason":"read","state":"pending","revision":1,"created_at":"2026-07-18T00:00:00Z","updated_at":"2026-07-18T00:00:00Z","presentation":{"title":"Read"}}`))
	}))
	defer server.Close()
	client, err := agentclient.New(agentclient.Options{Endpoint: strings.Replace(server.URL, "http://", "tcp://", 1), Credential: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(Config{
		Prefix: "test_", Client: func(context.Context) (*agentclient.Client, error) { return client, nil },
		Select: func(string) (Selection, error) { return Selection{Operation: "repo.read"}, nil },
		Prepare: func(_ context.Context, _ Selection, input *Input) error {
			input.Target = json.RawMessage(`{"kind":"repo"}`)
			return nil
		},
		Project: func(string, json.RawMessage) (json.RawMessage, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	value, err := bridge.Call(t.Context(), mcpserver.ToolCall{Name: "test_repo_read", Arguments: json.RawMessage(`{"target":{},"arguments":{},"reason":"read","request_id":"req_1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if submitted["operation"] != "repo.read" || value == nil {
		t.Fatalf("submitted = %#v, value = %#v", submitted, value)
	}
}

func TestBridgeRejectsInvalidReasonBeforeClient(t *testing.T) {
	bridge, err := New(Config{
		Prefix:  "test_",
		Client:  func(context.Context) (*agentclient.Client, error) { t.Fatal("client called"); return nil, nil },
		Select:  func(string) (Selection, error) { return Selection{Operation: "repo.read"}, nil },
		Prepare: func(context.Context, Selection, *Input) error { t.Fatal("prepare called"); return nil },
		Project: func(string, json.RawMessage) (json.RawMessage, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.Call(t.Context(), mcpserver.ToolCall{Name: "test_repo_read", Arguments: json.RawMessage(`{"target":{},"arguments":{},"reason":""}`)}); err == nil {
		t.Fatal("empty reason accepted")
	}
}

func TestBridgeOperationLifecycleUtilities(t *testing.T) {
	operation := `{"api_version":"brokerkit.io/agent/v1","id":"op_1","broker":"test","client_id":"agent","idempotency_key":"req_1","operation":"repo.read","target":{},"arguments":{},"reason":"read","state":"pending","revision":1,"created_at":"2026-07-18T00:00:00Z","updated_at":"2026-07-18T00:00:00Z","presentation":{"title":"Read"}}`
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/api/agent/v1/operations" {
			_, _ = writer.Write([]byte(`{"api_version":"brokerkit.io/agent/v1","operations":[` + operation + `],"next_cursor":null}`))
			return
		}
		if request.URL.Path == "/api/agent/v1/operations/op_1" || request.URL.Path == "/api/agent/v1/operations/op_1/cancel" {
			_, _ = writer.Write([]byte(operation))
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()
	client, err := agentclient.New(agentclient.Options{Endpoint: strings.Replace(server.URL, "http://", "tcp://", 1), Credential: testSecret})
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := New(Config{
		Prefix: "test_", Client: func(context.Context) (*agentclient.Client, error) { return client, nil },
		Select:  func(string) (Selection, error) { return Selection{}, errors.New("not an operation") },
		Prepare: func(context.Context, Selection, *Input) error { return nil },
		Project: func(_ string, value json.RawMessage) (json.RawMessage, error) { return value, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := []mcpserver.ToolCall{
		{Name: "test_operation_get", Arguments: json.RawMessage(`{"operation_id":"op_1"}`)},
		{Name: "test_operation_wait", Arguments: json.RawMessage(`{"operation_id":"op_1","timeout_seconds":0}`)},
		{Name: "test_operation_list", Arguments: json.RawMessage(`{"request_id":"req_1","limit":1}`)},
		{Name: "test_operation_cancel", Arguments: json.RawMessage(`{"operation_id":"op_1"}`)},
	}
	for _, call := range calls {
		if result, callErr := bridge.Call(t.Context(), call); callErr != nil || result == nil {
			t.Fatalf("%s = %#v, %v", call.Name, result, callErr)
		}
	}
	for _, call := range []mcpserver.ToolCall{
		{Name: "test_operation_unknown", Arguments: json.RawMessage(`{}`)},
		{Name: "test_operation_get", Arguments: json.RawMessage(`{"operation_id":"op_1","extra":true}`)},
	} {
		if _, callErr := bridge.Call(t.Context(), call); callErr == nil {
			t.Fatalf("%s accepted invalid input", call.Name)
		}
	}
}

func TestBridgeUtilityAndConfigurationFailures(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("incomplete bridge accepted")
	}
	want := errors.New("utility failed")
	bridge, err := New(Config{
		Prefix: "test_", Client: func(context.Context) (*agentclient.Client, error) { return nil, errors.New("client failed") },
		Select:  func(string) (Selection, error) { return Selection{}, errors.New("selection failed") },
		Prepare: func(context.Context, Selection, *Input) error { return nil },
		Project: func(string, json.RawMessage) (json.RawMessage, error) { return nil, nil },
		Utilities: map[string]func(context.Context, json.RawMessage) (any, error){
			"test_utility": func(context.Context, json.RawMessage) (any, error) { return nil, want },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = bridge.Call(t.Context(), mcpserver.ToolCall{Name: "test_utility", Arguments: json.RawMessage(`{}`)}); !errors.Is(err, want) {
		t.Fatalf("utility error = %v", err)
	}
	if _, err = bridge.Call(t.Context(), mcpserver.ToolCall{Name: "missing", Arguments: json.RawMessage(`{}`)}); err == nil {
		t.Fatal("selection error omitted")
	}
	bridge.config.Select = func(string) (Selection, error) { return Selection{Operation: "repo.read"}, nil }
	bridge.config.Prepare = func(context.Context, Selection, *Input) error { return errors.New("prepare failed") }
	valid := mcpserver.ToolCall{Name: "test_read", Arguments: json.RawMessage(`{"target":{},"arguments":{},"reason":"read"}`)}
	if _, err = bridge.Call(t.Context(), valid); err == nil {
		t.Fatal("prepare error omitted")
	}
	bridge.config.Prepare = func(context.Context, Selection, *Input) error { return nil }
	if _, err = bridge.Call(t.Context(), valid); err == nil {
		t.Fatal("client error omitted")
	}
}
