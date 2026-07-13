package hubclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestExecuteBoundUsesOnlyRegisteredMethodPathAndFixedFields(t *testing.T) {
	requests := make(chan *http.Request, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(request.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "hf_test_token")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.ExecuteBound(context.Background(), "bucket.delete",
		json.RawMessage(`{"namespace":"alice","repo":"old"}`), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	if request.Method != http.MethodDelete || request.URL.Path != "/api/buckets/alice/old" {
		t.Fatalf("request = %s %s", request.Method, request.URL.Path)
	}
	if err := client.ExecuteBound(context.Background(), "webhook.enable",
		json.RawMessage(`{"webhookId":"0123456789abcdef01234567"}`), json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	request = <-requests
	if request.Method != http.MethodPost || request.URL.Path != "/api/settings/webhooks/0123456789abcdef01234567/enable" {
		t.Fatalf("request = %s %s", request.Method, request.URL.Path)
	}
}

func TestExecuteBoundEmitsRegisteredQueryParameters(t *testing.T) {
	requests := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests <- request.Clone(request.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	client, err := New(server.URL, "hf_test_token")
	if err != nil {
		t.Fatal(err)
	}
	target := json.RawMessage(`{"repoType":"dataset","repoName":"acme/demo","readStatus":"unread","applyToAll":true,"p":2}`)
	if err := client.ExecuteBound(t.Context(), "notification.delete", target, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	request := <-requests
	if request.URL.Path != "/api/notifications" || request.URL.Query().Get("repoName") != "acme/demo" ||
		request.URL.Query().Get("applyToAll") != "true" || request.URL.Query().Get("p") != "2" {
		t.Fatalf("request URL = %s", request.URL.String())
	}
}

func TestBoundQueryValueEncoding(t *testing.T) {
	query := make(url.Values)
	if !appendBoundQueryValue(query, "tag", []any{"one", json.Number("2")}) || len(query["tag"]) != 2 {
		t.Fatalf("array query = %v", query)
	}
	if appendBoundQueryValue(query, "bad", []any{map[string]any{"nested": true}}) {
		t.Fatal("object query item was accepted")
	}
	if value, valid := scalarQueryValue(1.5); !valid || value != "1.5" {
		t.Fatalf("float query = %q, %v", value, valid)
	}
	if _, valid := scalarQueryValue(json.Number("bad")); valid {
		t.Fatal("invalid JSON number was accepted")
	}
	if _, valid := scalarQueryValue(map[string]any{}); valid {
		t.Fatal("object query was accepted")
	}
	if _, err := renderBoundQuery([]string{"filter"}, json.RawMessage(`{"filter":{"nested":true}}`)); err == nil {
		t.Fatal("nested bound query was accepted")
	}
}

func TestExecuteBoundRejectsUnknownOperationAndPathFields(t *testing.T) {
	client, _ := New("https://huggingface.co", "hf_test_token")
	for _, test := range []struct {
		operation string
		target    string
	}{
		{operation: "http.request", target: `{}`},
		{operation: "bucket.delete", target: `{"namespace":"alice"}`},
		{operation: "bucket.delete", target: `{"namespace":"alice","repo":"../admin"}`},
	} {
		if err := client.ExecuteBound(context.Background(), test.operation, json.RawMessage(test.target), json.RawMessage(`{}`)); err == nil {
			t.Fatalf("unsafe operation accepted: %+v", test)
		}
	}
}

func TestBoundResultAndObservationStayOnRegisteredRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"id":"resource-1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"token":"generated-secret"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "hf_test_token", WithHTTPTransport(server.Client().Transport))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ExecuteBoundResult(context.Background(), "service_account.token.create",
		json.RawMessage(`{"name":"acme","serviceAccountId":"service-1"}`), json.RawMessage(`{"name":"automation"}`))
	if err != nil || string(result) != `{"token":"generated-secret"}` {
		t.Fatalf("ExecuteBoundResult() = %s, %v", result, err)
	}
	observed, absent, err := client.ObserveBound(context.Background(), "collection.delete",
		json.RawMessage(`{"namespace":"acme","slug":"review","id":"123"}`))
	if err != nil || absent || string(observed) != `{"id":"resource-1"}` {
		t.Fatalf("ObserveBound() = %s, %v, %v", observed, absent, err)
	}
}

func TestObserveBoundTreatsNotFoundAsAbsence(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	client, _ := New(server.URL, "hf_test_token", WithHTTPTransport(server.Client().Transport))
	observed, absent, err := client.ObserveBound(context.Background(), "collection.delete",
		json.RawMessage(`{"namespace":"acme","slug":"review","id":"123"}`))
	if err != nil || !absent || observed != nil {
		t.Fatalf("ObserveBound() = %s, %v, %v", observed, absent, err)
	}
}
