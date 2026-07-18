package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testServer(t *testing.T, tools func(context.Context) ([]map[string]any, error)) *Server {
	t.Helper()
	server, err := New(Config{Name: "test-broker", Version: "1.2.3", ListChanged: true, Tools: tools,
		Call: func(_ context.Context, call ToolCall) (any, error) {
			if call.Name == "fail" {
				return nil, errors.New("refused")
			}
			return map[string]any{"name": call.Name}, nil
		},
		Resources: func(context.Context) ([]map[string]any, error) {
			return []map[string]any{{"uri": "test://catalog"}}, nil
		},
		ReadResource: func(_ context.Context, input ResourceRead) (any, error) {
			return map[string]any{"uri": input.URI}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestServeProtocolAndToolResults(t *testing.T) {
	tools := func(context.Context) ([]map[string]any, error) {
		return []map[string]any{{"name": "ok"}}, nil
	}
	input := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ok","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fail","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"test://catalog"}}`,
	}, "\n")
	var output bytes.Buffer
	if err := testServer(t, tools).Serve(t.Context(), strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var responses []map[string]any
	decoder := json.NewDecoder(&output)
	for decoder.More() {
		var response map[string]any
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		responses = append(responses, response)
	}
	if len(responses) != 4 {
		t.Fatalf("responses = %d, want 4: %s", len(responses), output.String())
	}
	capabilities := responses[0]["result"].(map[string]any)["capabilities"].(map[string]any)
	if capabilities["resources"] == nil {
		t.Fatal("initialize omitted resources capability")
	}
	failed := responses[2]["result"].(map[string]any)
	if failed["isError"] != true {
		t.Fatalf("failed tool = %#v", failed)
	}
}

func TestServeRejectsInvalidAndDuplicateJSON(t *testing.T) {
	tools := func(context.Context) ([]map[string]any, error) { return nil, nil }
	input := "not-json\n" + `{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}` + "\n"
	var output bytes.Buffer
	if err := testServer(t, tools).Serve(t.Context(), strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(output.String(), `"code":-32700`); count != 2 {
		t.Fatalf("parse errors = %d, want 2: %s", count, output.String())
	}
}

func TestServeEmitsToolChangeNotification(t *testing.T) {
	calls := 0
	tools := func(context.Context) ([]map[string]any, error) {
		calls++
		return []map[string]any{{"name": string(rune('a' + calls))}}, nil
	}
	var output bytes.Buffer
	if err := testServer(t, tools).Serve(t.Context(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`+"\n"), &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "notifications/tools/list_changed") {
		t.Fatalf("missing notification: %s", output.String())
	}
}

func TestNewRequiresCoreHandlers(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted incomplete configuration")
	}
}
