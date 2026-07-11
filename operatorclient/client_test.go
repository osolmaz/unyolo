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
	"github.com/osolmaz/brokerkit/operatorv1"
	"github.com/osolmaz/brokerkit/policy"
)

func TestClientImplementsOperatorV1Source(t *testing.T) {
	t.Parallel()
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		paths = append(paths, request.URL.RequestURI())
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path != "/healthz" && request.Header.Get("Authorization") != "Bearer operator-token" {
			writeError(writer, http.StatusUnauthorized, "unauthorized")
			return
		}
		switch request.URL.Path {
		case "/healthz":
			_, _ = writer.Write([]byte(`{"status":"ok"}`))
		case "/.well-known/brokerkit-operator":
			_ = json.NewEncoder(writer).Encode(operatorv1.Descriptor{APIVersion: operatorv1.APIVersion})
		case "/api/operator/v1/requests":
			_ = json.NewEncoder(writer).Encode(operatorv1.Page{Requests: []operatorv1.Request{{ID: "request-1", Revision: 1}}})
		case "/api/operator/v1/requests/missing":
			writeError(writer, http.StatusNotFound, "not_found")
		default:
			_ = json.NewEncoder(writer).Encode(operatorv1.Request{ID: "request-1", Revision: 2, Status: grants.StatusActive})
		}
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, Token: "operator-token", HTTPClient: server.Client()}
	if descriptor, err := client.Discover(t.Context()); err != nil || descriptor.APIVersion != operatorv1.APIVersion {
		t.Fatalf("Discover() = %+v, %v", descriptor, err)
	}
	if err := client.Health(t.Context()); err != nil {
		t.Fatal(err)
	}
	page, err := client.List(t.Context(), operatorv1.Query{Status: grants.StatusGroupPending, Requester: "bob", Operation: "write", Limit: 5,
		Target: &policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}}})
	if err != nil || len(page.Requests) != 1 {
		t.Fatalf("List() = %+v, %v", page, err)
	}
	if !strings.Contains(paths[2], "requester=bob") || !strings.Contains(paths[2], "target.name=demo") {
		t.Fatalf("list path = %s", paths[2])
	}
	if _, err := client.Get(t.Context(), "request-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(t.Context(), "request-1", operatorv1.ActionApprove, operatorv1.Decision{ExpectedRevision: 1, IdempotencyKey: "decision-1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Get(t.Context(), "missing"); err == nil {
		t.Fatal("Get(missing) returned no error")
	} else {
		var apiErr *Error
		if !errors.As(err, &apiErr) || apiErr.Code != "not_found" {
			t.Fatalf("error = %#v", err)
		}
	}
}

func TestClientWatchesOperatorV1Events(t *testing.T) {
	t.Parallel()
	event := operatorv1.Event{Cursor: "cursor-1", Kind: "request.created", RequestID: "request-1", Revision: 1, Status: grants.StatusPending}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/operator/v1/events" {
			t.Errorf("path = %s", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "text/event-stream")
		encoded, _ := json.Marshal(event)
		_, _ = fmt.Fprintf(writer, "id: %s\ndata: %s\n\n", event.Cursor, encoded)
	}))
	defer server.Close()
	stream, err := (&Client{BaseURL: server.URL, HTTPClient: server.Client()}).Watch(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	received, err := stream.Receive(t.Context())
	if err != nil || received.Cursor != event.Cursor {
		t.Fatalf("Receive() = %+v, %v", received, err)
	}
}

func TestEventReceiveCancellationClosesBlockedStream(t *testing.T) {
	t.Parallel()
	handlerDone := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		defer close(handlerDone)
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.WriteHeader(http.StatusOK)
		writer.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()
	stream, err := (&Client{BaseURL: server.URL, HTTPClient: server.Client()}).Watch(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if _, err := stream.Receive(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Receive() error = %v", err)
	}
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("canceled receive did not close the event response")
	}
}

func TestClientRejectsWrongResponseMediaTypes(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/plain")
		if request.URL.Path == "/api/operator/v1/events" {
			_, _ = writer.Write([]byte("data: {}\n\n"))
			return
		}
		_, _ = writer.Write([]byte(`{"api_version":"operator.v1"}`))
	}))
	defer server.Close()
	client := &Client{BaseURL: server.URL, HTTPClient: server.Client()}
	if _, err := client.Discover(t.Context()); err == nil {
		t.Fatal("Discover() accepted text/plain")
	}
	if _, err := client.Watch(t.Context(), ""); err == nil {
		t.Fatal("Watch() accepted text/plain")
	}
}

func TestClientDropsUnknownResponseFieldsAndRejectsTrailingData(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"api_version":%q,"unknown":{"unsafe":"dropped"}}`, operatorv1.APIVersion)
	}))
	defer server.Close()
	if descriptor, err := (&Client{BaseURL: server.URL, HTTPClient: server.Client()}).Discover(t.Context()); err != nil || descriptor.APIVersion != operatorv1.APIVersion {
		t.Fatalf("Discover(unknown output) = %+v, %v", descriptor, err)
	}
	trailing := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"api_version":%q}{}`, operatorv1.APIVersion)
	}))
	defer trailing.Close()
	if _, err := (&Client{BaseURL: trailing.URL, HTTPClient: trailing.Client()}).Discover(t.Context()); err == nil {
		t.Fatal("Discover() accepted trailing response data")
	}
	if _, err := NewUnix("relative.sock", "token"); err == nil {
		t.Fatal("NewUnix() accepted a relative socket path")
	}
}

func writeError(writer http.ResponseWriter, status int, code string) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(operatorv1.ErrorEnvelope{Error: operatorv1.Error{Code: code, Message: "failed", CorrelationID: "correlation"}})
}
