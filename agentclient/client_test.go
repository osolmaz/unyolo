package agentclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
)

const testCredential = "agent-credential-with-enough-entropy"

func TestClientSubmitGetAndWait(t *testing.T) {
	t.Parallel()
	var waits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer "+testCredential {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		operation := testOperation(agentv1.StatePending)
		if strings.HasSuffix(request.URL.Path, "/events") && waits.Add(1) > 1 {
			operation["state"] = agentv1.StateSucceeded
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(operation)
	}))
	defer server.Close()
	client := newTestClient(t, server.URL, nil)
	request := agentv1.SubmitRequest{IdempotencyKey: "request", Operation: "repo.create", Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Reason: "test"}
	operation, err := client.Submit(t.Context(), request)
	if err != nil || operation.ID != "op" {
		t.Fatalf("Submit() = %+v, %v", operation, err)
	}
	operation, err = client.Get(t.Context(), operation.ID)
	if err != nil || operation.ID != "op" {
		t.Fatalf("Get() = %+v, %v", operation, err)
	}
	operation, err = client.Wait(t.Context(), operation)
	if err != nil || operation.State != agentv1.StateSucceeded {
		t.Fatalf("Wait() = %+v, %v", operation, err)
	}
}

func TestClientWaitReturnsLastOperationOnCancellation(t *testing.T) {
	t.Parallel()
	client := newTestClient(t, "http://127.0.0.1:1", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})})
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	initial := domainOperation(agentv1.StatePending)
	operation, err := client.Wait(ctx, initial)
	if !errors.Is(err, context.Canceled) || operation.ID != initial.ID {
		t.Fatalf("Wait() = %+v, %v", operation, err)
	}
}

func TestClientRejectsInvalidConfigurationRedirectsAndResponses(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("New() accepted empty options")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", "https://example.com")
		writer.WriteHeader(http.StatusFound)
	}))
	defer redirect.Close()
	provided := &http.Client{}
	client := newTestClient(t, redirect.URL, provided)
	if _, err := client.Get(t.Context(), "op"); err == nil {
		t.Fatal("Get() followed or accepted redirect")
	}
	if provided.CheckRedirect != nil {
		t.Fatal("New() mutated provided HTTP client")
	}
	for status, body := range map[int]string{
		http.StatusForbidden: `{"error":{"code":"denied","message":"no"}}`,
		http.StatusOK:        `{}`,
	} {
		_, err := decodeResponse(status, []byte(body))
		if err == nil {
			t.Fatalf("decodeResponse(%d) succeeded", status)
		}
	}
}

func newTestClient(t *testing.T, baseURL string, httpClient *http.Client) *Client {
	t.Helper()
	client, err := New(Options{BaseURL: baseURL, Credential: testCredential, HTTPClient: httpClient})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func domainOperation(state agentv1.State) agentv1.Operation {
	return agentv1.Operation{APIVersion: agentv1.APIVersion, ID: "op", State: state}
}

func testOperation(state agentv1.State) map[string]any {
	return map[string]any{
		"api_version": agentv1.APIVersion, "id": "op", "broker": "test", "client_id": "client",
		"idempotency_key": "request", "operation": "repo.create", "target": map[string]any{}, "arguments": map[string]any{},
		"reason": "test", "state": state, "revision": 1, "created_at": time.Now().UTC(), "updated_at": time.Now().UTC(),
		"presentation": map[string]any{"title": "Test"},
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }
