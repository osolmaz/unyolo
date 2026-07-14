package mcpoperation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
)

type fakeClient struct {
	operation agentv1.Operation
	page      agentv1.OperationPage
	waitErr   error
}

func (f *fakeClient) Get(context.Context, string) (agentv1.Operation, error) { return f.operation, nil }
func (f *fakeClient) List(context.Context, agentv1.ListOptions) (agentv1.OperationPage, error) {
	return f.page, nil
}
func (f *fakeClient) Wait(context.Context, agentv1.Operation) (agentv1.Operation, error) {
	return f.operation, f.waitErr
}

func TestResolveRequestID(t *testing.T) {
	if value, err := resolveRequestID(" exact.one ", bytes.NewReader(nil)); err != nil || value != "exact.one" {
		t.Fatalf("supplied = %q, %v", value, err)
	}
	value, err := resolveRequestID("", bytes.NewReader(make([]byte, 18)))
	if err != nil || len(value) != 28 || value[:4] != "req_" {
		t.Fatalf("generated = %q, %v", value, err)
	}
	if _, err := resolveRequestID("bad value", bytes.NewReader(nil)); err == nil {
		t.Fatal("invalid supplied ID accepted")
	}
	if _, err := resolveRequestID("", bytes.NewReader(nil)); err == nil {
		t.Fatal("entropy failure accepted")
	}
}

func TestProjectGetWaitAndList(t *testing.T) {
	now := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	operation := agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: "op", Broker: "test", ClientID: "agent", IdempotencyKey: "req",
		Operation: "repo.read", State: agentv1.StateSucceeded, Revision: 2, CreatedAt: now, UpdatedAt: now,
		Presentation: agentv1.Presentation{Title: "Read"}, Result: json.RawMessage(`{"key":"value"}`),
	}
	summary := agentv1.OperationSummary{
		APIVersion: agentv1.APIVersion, ID: operation.ID, Broker: operation.Broker, ClientID: operation.ClientID,
		IdempotencyKey: operation.IdempotencyKey, Operation: operation.Operation, State: operation.State,
		Revision: operation.Revision, CreatedAt: now, UpdatedAt: now, Presentation: operation.Presentation,
	}
	client := &fakeClient{operation: operation, page: agentv1.OperationPage{APIVersion: agentv1.APIVersion, Operations: []agentv1.OperationSummary{summary}}}
	project := func(_ string, raw json.RawMessage) (json.RawMessage, error) {
		return bytes.ReplaceAll(raw, []byte(`"key"`), []byte(`"document_name"`)), nil
	}
	got, err := Get(t.Context(), client, GetInput{OperationID: "op"}, project)
	if err != nil || got.RequestID != "req" || !bytes.Contains(got.Result, []byte("document_name")) {
		t.Fatalf("get = %+v, %v", got, err)
	}
	zero := 0
	got, err = Wait(t.Context(), client, WaitInput{OperationID: "op", TimeoutSeconds: &zero}, project)
	if err != nil || got.State != agentv1.StateSucceeded {
		t.Fatalf("wait = %+v, %v", got, err)
	}
	page, err := List(t.Context(), client, ListInput{})
	if err != nil || page.APIVersion != PageAPIVersion || len(page.Operations) != 1 || page.Operations[0].RequestID != "req" {
		t.Fatalf("list = %+v, %v", page, err)
	}
	if _, err := Project(operation, nil); err == nil {
		t.Fatal("result without projector accepted")
	}
}

func TestConflictProjection(t *testing.T) {
	summary := agentv1.OperationSummary{ID: "op", IdempotencyKey: "req", Operation: "repo.create", State: agentv1.StatePending, Revision: 1}
	client := &fakeClient{page: agentv1.OperationPage{Operations: []agentv1.OperationSummary{summary}}}
	err := Conflict(t.Context(), client, "req", &agentclient.Error{Status: 409, Code: "idempotency_conflict", Message: "conflict"})
	value := ErrorValue(err)
	if value["code"] != "request_id_conflict" || value["existing"].(ConflictExisting).ID != "op" {
		t.Fatalf("conflict = %#v", value)
	}
	original := errors.New("other")
	if Conflict(t.Context(), client, "req", original) != original {
		t.Fatal("unrelated error changed")
	}
}
