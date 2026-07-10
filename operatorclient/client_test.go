package operatorclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

func TestClientRoutesAndErrors(t *testing.T) { //nolint:cyclop,gocognit // One wire-contract scenario covers every client method.
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.RequestURI())
		if request.Header.Get("Authorization") != "Bearer operator-token" {
			writeClientTestError(writer, http.StatusUnauthorized, "unauthorized")
			return
		}
		if strings.Contains(request.URL.Path, "/missing") {
			writeClientTestError(writer, http.StatusNotFound, "not_found")
			return
		}
		item := operatorinbox.Item{ID: "grant-1", Revision: 2, Status: grants.StatusPending}
		if request.URL.Path == "/api/grants" {
			_ = json.NewEncoder(writer).Encode(operatorinbox.Page{Items: []operatorinbox.Item{item}})
			return
		}
		_ = json.NewEncoder(writer).Encode(item)
	}))
	t.Cleanup(server.Close)
	client := &Client{BaseURL: server.URL, Token: "operator-token", HTTPClient: server.Client()}
	query := grants.Query{
		StatusGroup: grants.StatusGroupPending, Client: "bob", Operation: "provider.write", Cursor: "cursor", Limit: 5,
		Target: &policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
	}
	page, err := client.List(t.Context(), query)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	if !strings.Contains(paths[0], "target.name=demo") || !strings.Contains(paths[0], "status=pending") {
		t.Fatalf("list path = %s", paths[0])
	}
	if _, err := client.Get(t.Context(), "grant-1"); err != nil {
		t.Fatal(err)
	}
	decision := Decision{ExpectedRevision: 2, ExpectedStatus: grants.StatusPending, Reason: "reviewed", Duration: time.Minute, MaxUses: 1}
	for name, call := range map[string]func(context.Context, string, Decision) (operatorinbox.Item, error){
		"approve": client.Approve, "deny": client.Deny, "cancel": client.Cancel, "revoke": client.Revoke,
	} {
		if _, err := call(t.Context(), "grant-1", decision); err != nil {
			t.Fatalf("%s error = %v", name, err)
		}
	}
	if _, err := client.Get(t.Context(), "missing"); err == nil {
		t.Fatal("Get(missing) returned no error")
	} else {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
			t.Fatalf("Get(missing) error = %#v", err)
		}
	}
	if _, err := (&Client{}).Get(t.Context(), "grant"); err == nil {
		t.Fatal("client without BaseURL returned no error")
	}
	if _, err := client.Approve(t.Context(), "grant-1", Decision{ExpectedRevision: 2, Duration: 500 * time.Millisecond}); err == nil {
		t.Fatal("Approve() accepted a sub-second duration")
	}
}

func TestClientStreamParsesEventsAndStopsOnReceiver(t *testing.T) {
	event := grants.Event{Cursor: "cursor-1", Kind: grants.EventRequestCreated, GrantID: "grant-1", Status: grants.StatusPending, Revision: 1}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "text/event-stream")
		data, _ := json.Marshal(event)
		_, _ = fmt.Fprintf(writer, "id: cursor-1\nevent: request.created\ndata: %s\n\n", data)
	}))
	t.Cleanup(server.Close)
	stop := errors.New("stop")
	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	err := client.StreamEvents(t.Context(), "", func(received grants.Event) error {
		if received.Cursor != event.Cursor {
			t.Fatalf("event = %+v", received)
		}
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("StreamEvents() error = %v", err)
	}
}

func TestClientStreamRejectsTerminalAndMalformedEvents(t *testing.T) {
	t.Run("cursor expired", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writeClientTestError(writer, http.StatusGone, "cursor_expired")
		}))
		defer server.Close()
		err := (&Client{BaseURL: server.URL, HTTPClient: server.Client()}).StreamEvents(t.Context(), "old", func(grants.Event) error { return nil })
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Status != http.StatusGone {
			t.Fatalf("StreamEvents() error = %#v", err)
		}
	})
	t.Run("cursor mismatch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = writer.Write([]byte("id: one\ndata: {\"cursor\":\"two\"}\n\n"))
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
		defer cancel()
		err := (&Client{BaseURL: server.URL, HTTPClient: server.Client()}).StreamEvents(ctx, "", func(grants.Event) error { return nil })
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("StreamEvents() error = %v", err)
		}
	})
}

func TestClientLowLevelResponseAndStreamErrors(t *testing.T) { //nolint:cyclop // Table covers transport decoder branches.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/grants/events" {
			switch request.URL.Query().Get("cursor") {
			case "bad":
				_, _ = writer.Write([]byte("id: cursor\ndata: not-json\n\n"))
			case "good":
				_, _ = writer.Write([]byte("id: cursor\ndata: {\"cursor\":\"cursor\",\"kind\":\"request.created\"}\n\n"))
			default:
				writer.WriteHeader(http.StatusBadGateway)
				_, _ = writer.Write([]byte("not-json"))
			}
			return
		}
		switch request.URL.Path {
		case "/malformed":
			_, _ = writer.Write([]byte("not-json"))
		case "/plain-error":
			writer.WriteHeader(http.StatusBadGateway)
			_, _ = writer.Write([]byte("not-json"))
		default:
			_ = json.NewEncoder(writer).Encode(operatorinbox.Page{})
		}
	}))
	t.Cleanup(server.Close)
	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	if _, err := client.List(t.Context(), grants.Query{}); err != nil {
		t.Fatal(err)
	}
	if err := client.doJSON(t.Context(), http.MethodGet, "/malformed", nil, &operatorinbox.Item{}); err == nil {
		t.Fatal("doJSON() accepted malformed success body")
	}
	if err := client.doJSON(t.Context(), http.MethodGet, "/plain-error", nil, &operatorinbox.Item{}); err == nil {
		t.Fatal("doJSON() accepted malformed error body")
	}
	if err := client.doJSON(t.Context(), http.MethodPost, "/", make(chan int), &operatorinbox.Item{}); err == nil {
		t.Fatal("doJSON() accepted unsupported body")
	}
	if _, err := client.streamOnce(t.Context(), "", func(grants.Event) error { return nil }); err == nil {
		t.Fatal("streamOnce() accepted non-SSE JSON response")
	}
	if _, err := client.streamOnce(t.Context(), "bad", func(grants.Event) error { return nil }); err == nil {
		t.Fatal("streamOnce() accepted malformed event")
	}
	received := false
	if cursor, err := client.streamOnce(t.Context(), "good", func(grants.Event) error { received = true; return nil }); err != nil || cursor != "cursor" || !received {
		t.Fatalf("streamOnce() = %q, %v, received=%v", cursor, err, received)
	}
}

func writeClientTestError(writer http.ResponseWriter, status int, code string) {
	writer.WriteHeader(status)
	_, _ = fmt.Fprintf(writer, `{"error":{"code":%q,"message":"failed"}}`, code)
}
