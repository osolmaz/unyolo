package operations

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
)

func TestRepositoryCreateAndDeleteAdapters(t *testing.T) {
	var mu sync.Mutex
	exists := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/datasets/acme/demo":
			if !exists {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"id":"acme/demo","sha":"abc","private":true}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/repos/create":
			assertBody(t, r, `{"name":"demo","organization":"acme","type":"dataset","visibility":"private"}`)
			exists = true
			_, _ = w.Write([]byte(`{"url":"ignored"}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/repos/delete":
			assertBody(t, r, `{"name":"demo","organization":"acme","type":"dataset"}`)
			exists = false
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	hub, _ := hubclient.New(server.URL, "token", server.Client())
	adapters, err := NewRepositoryAdapters(hub, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	target := json.RawMessage(`{"kind":"repo","type":"dataset","owner":"acme","name":"demo"}`)
	create, _ := registry.Lookup("repo.create")
	input, err := create.Decode(target, json.RawMessage(`{"visibility":"private"}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := create.Resolve(context.Background(), input)
	if err != nil || plan.Policy.Target.Owner != "acme" || !strings.Contains(plan.Presentation.Summary, "private") {
		t.Fatalf("create plan = %+v, %v", plan, err)
	}
	if _, err := create.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if outcome, err := create.Reconcile(context.Background(), plan); err != nil || !outcome.Proven {
		t.Fatalf("create reconciliation = %+v, %v", outcome, err)
	}

	deleteAdapter, _ := registry.Lookup("repo.delete")
	input, _ = deleteAdapter.Decode(target, json.RawMessage(`{}`))
	plan, err = deleteAdapter.Resolve(context.Background(), input)
	if err != nil || !strings.Contains(plan.Presentation.Summary, "Permanently") {
		t.Fatalf("delete plan = %+v, %v", plan, err)
	}
	if _, err := deleteAdapter.Execute(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if outcome, err := deleteAdapter.Reconcile(context.Background(), plan); err != nil || !outcome.Proven {
		t.Fatalf("delete reconciliation = %+v, %v", outcome, err)
	}
}

func TestRepositoryAdaptersRejectUnknownFieldsAndStalePlans(t *testing.T) {
	body := `{"id":"acme/demo","sha":"abc"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }))
	defer server.Close()
	hub, _ := hubclient.New(server.URL, "token", server.Client())
	adapters, _ := NewRepositoryAdapters(hub, server.URL)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("repo.delete")
	target := json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo"}`)
	for _, invalid := range []json.RawMessage{json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo","url":"https://attacker"}`), json.RawMessage(`{"kind":"repo","kind":"repo","type":"model","owner":"acme","name":"demo"}`)} {
		if _, err := adapter.Decode(invalid, json.RawMessage(`{}`)); err == nil {
			t.Fatalf("invalid target accepted: %s", invalid)
		}
	}
	input, _ := adapter.Decode(target, json.RawMessage(`{}`))
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	body = `{"id":"acme/demo","sha":"changed"}`
	if _, err := adapter.Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("stale plan error = %v", err)
	}
}

func TestRegistryReportsMissingCoverage(t *testing.T) {
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.ValidateCoverage(); err == nil || !strings.Contains(err.Error(), "repo.delete") {
		t.Fatalf("coverage error = %v", err)
	}
}

func TestRepositoryDeleteUnknownResultReconciles(t *testing.T) {
	// Reconciliation is authoritative even when the mutation response was lost.
	hub := &scriptedClient{responses: []scriptedResponse{
		{body: json.RawMessage(`{"id":"acme/demo","sha":"abc"}`)},
		{body: json.RawMessage(`{"id":"acme/demo","sha":"abc"}`)},
		{err: &hubclient.Error{Code: hubclient.CodeUnknownResult, Ambiguous: true}},
		{err: &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: http.StatusNotFound}},
	}}
	adapters, _ := NewRepositoryAdapters(hub, "https://huggingface.co")
	adapter := adapters[1]
	input, _ := adapter.Decode(json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo"}`), json.RawMessage(`{}`))
	plan, _ := adapter.Resolve(context.Background(), input)
	if _, err := adapter.Execute(context.Background(), plan); err == nil {
		t.Fatal("ambiguous delete did not fail")
	}
	if outcome, err := adapter.Reconcile(context.Background(), plan); err != nil || !outcome.Proven {
		t.Fatalf("reconciliation = %+v, %v", outcome, err)
	}
}

type scriptedResponse struct {
	body json.RawMessage
	err  error
}

type scriptedClient struct {
	responses []scriptedResponse
}

func (c *scriptedClient) Do(context.Context, hubclient.Call) (hubclient.Response, error) {
	if len(c.responses) == 0 {
		return hubclient.Response{}, errors.New("unexpected call")
	}
	next := c.responses[0]
	c.responses = c.responses[1:]
	return hubclient.Response{Body: next.body}, next.err
}

func assertBody(t *testing.T, request *http.Request, expected string) {
	t.Helper()
	var got, want any
	if json.NewDecoder(request.Body).Decode(&got) != nil || json.Unmarshal([]byte(expected), &want) != nil {
		t.Fatal("could not decode request body")
	}
	if !equalJSONValue(got, want) {
		t.Fatalf("body = %#v, want %#v", got, want)
	}
}

func equalJSONValue(left, right any) bool {
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	return string(leftJSON) == string(rightJSON)
}
