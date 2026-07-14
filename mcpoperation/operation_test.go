package mcpoperation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentclient"
	"github.com/osolmaz/brokerkit/agentv1"
)

type fakeClient struct {
	operation agentv1.Operation
	page      agentv1.OperationPage
	getErr    error
	listErr   error
	waitErr   error
	wait      func(context.Context, agentv1.Operation) (agentv1.Operation, error)
	getID     string
}

func (f *fakeClient) Get(_ context.Context, id string) (agentv1.Operation, error) {
	f.getID = id
	return f.operation, f.getErr
}
func (f *fakeClient) List(context.Context, agentv1.ListOptions) (agentv1.OperationPage, error) {
	return f.page, f.listErr
}
func (f *fakeClient) Wait(ctx context.Context, operation agentv1.Operation) (agentv1.Operation, error) {
	if f.wait != nil {
		return f.wait(ctx, operation)
	}
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
	if _, err := Get(t.Context(), client, GetInput{OperationID: " op "}, project); err != nil || client.getID != "op" {
		t.Fatalf("trimmed get ID = %q, %v", client.getID, err)
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
	if !errors.Is(Conflict(t.Context(), client, "req", original), original) {
		t.Fatal("unrelated error changed")
	}
	conflict := &agentclient.Error{Status: 409, Code: "idempotency_conflict", Message: "conflict"}
	client.page = agentv1.OperationPage{}
	if value := ErrorValue(Conflict(t.Context(), client, "req", conflict)); value["code"] != nil || value["existing"] != nil {
		t.Fatalf("incomplete conflict was structured: %#v", value)
	}
}

func TestProjectionRejectsInvalidLegacyRequestIDs(t *testing.T) {
	operation := agentv1.Operation{ID: "op", IdempotencyKey: "bad value", Operation: "repo.read", State: agentv1.StatePending, Revision: 1}
	if _, err := Project(operation, nil); err == nil {
		t.Fatal("invalid operation request ID accepted")
	}
	client := &fakeClient{page: agentv1.OperationPage{Operations: []agentv1.OperationSummary{{
		ID: "op", IdempotencyKey: "bad value", Operation: "repo.read", State: agentv1.StatePending, Revision: 1,
	}}}}
	if _, err := List(t.Context(), client, ListInput{}); err == nil {
		t.Fatal("invalid page request ID accepted")
	}
}

func TestWaitFollowsPendingOperation(t *testing.T) {
	operation := agentv1.Operation{ID: "op", IdempotencyKey: "req", State: agentv1.StatePending}
	client := &fakeClient{operation: operation}
	seconds := 1
	got, err := Wait(t.Context(), client, WaitInput{OperationID: " op ", TimeoutSeconds: &seconds}, nil)
	if err != nil || got.ID != "op" {
		t.Fatalf("Wait() = %+v, %v", got, err)
	}

	client.waitErr = errors.New("wait failed")
	if _, err := Wait(t.Context(), client, WaitInput{OperationID: "op", TimeoutSeconds: &seconds}, nil); !errors.Is(err, client.waitErr) {
		t.Fatalf("Wait() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client.wait = func(ctx context.Context, operation agentv1.Operation) (agentv1.Operation, error) {
		return operation, ctx.Err()
	}
	if _, err := Wait(ctx, client, WaitInput{OperationID: "op", TimeoutSeconds: &seconds}, nil); err != nil {
		t.Fatalf("Wait() canceled recovery = %v", err)
	}
}

func TestOperationRecoveryRejectsInvalidInputsAndClientErrors(t *testing.T) {
	client := &fakeClient{getErr: errors.New("get failed"), listErr: errors.New("list failed")}
	if _, err := Get(t.Context(), client, GetInput{OperationID: "op"}, nil); !errors.Is(err, client.getErr) {
		t.Fatalf("Get() error = %v", err)
	}
	if _, err := Wait(t.Context(), client, WaitInput{}, nil); err == nil {
		t.Fatal("Wait() accepted an empty operation ID")
	}
	if _, err := List(t.Context(), client, ListInput{}); !errors.Is(err, client.listErr) {
		t.Fatalf("List() error = %v", err)
	}
	tooMany := MaxListLimit + 1
	for _, input := range []ListInput{
		{RequestID: "bad value"},
		{Cursor: strings.Repeat("c", 129)},
		{Limit: &tooMany},
	} {
		if _, err := List(t.Context(), client, input); err == nil {
			t.Fatalf("List() accepted %+v", input)
		}
	}
}
