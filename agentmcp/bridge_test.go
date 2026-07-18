package agentmcp

import (
	"context"
	"encoding/json"
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
