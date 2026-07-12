package state

import (
	"errors"
	"testing"
	"time"
)

func TestOperationRepositoryLifecycle(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	record := OperationRecord{
		ID: "op_one", APIVersion: "brokerkit.io/agent/v1", Broker: "hf-broker",
		ClientID: "agent", IdempotencyKey: "one", Operation: "repo.create",
		TargetJSON: []byte(`{"kind":"repo"}`), ArgumentsJSON: []byte(`{}`),
		Reason: "create", State: "pending", Revision: 1, CreatedAt: now, UpdatedAt: now,
		PresentationJSON: []byte(`{"title":"Create","summary":""}`),
	}
	if err := database.InsertOperation(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := database.InsertOperation(t.Context(), record); err == nil {
		t.Fatal("duplicate operation unexpectedly inserted")
	}
	byID, err := database.OperationByID(t.Context(), record.ID)
	if err != nil || byID.IdempotencyKey != record.IdempotencyKey {
		t.Fatalf("OperationByID() = %+v, %v", byID, err)
	}
	byKey, err := database.OperationByIdempotency(t.Context(), record.ClientID, record.IdempotencyKey)
	if err != nil || byKey.ID != record.ID {
		t.Fatalf("OperationByIdempotency() = %+v, %v", byKey, err)
	}
	if _, err := database.OperationForClient(t.Context(), record.ID, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("OperationForClient(other) = %v", err)
	}
	if unfinished, err := database.UnfinishedOperations(t.Context()); err != nil || len(unfinished) != 1 {
		t.Fatalf("UnfinishedOperations() = %+v, %v", unfinished, err)
	}
	record.State = "succeeded"
	record.Revision = 2
	record.UpdatedAt = now.Add(time.Minute)
	record.TerminalAt = &record.UpdatedAt
	record.ResultJSON = []byte(`{"repo_id":"alice/data"}`)
	if updated, err := database.UpdateOperation(t.Context(), record, 0); err != nil || updated {
		t.Fatalf("stale UpdateOperation() = %v, %v", updated, err)
	}
	if updated, err := database.UpdateOperation(t.Context(), record, 1); err != nil || !updated {
		t.Fatalf("UpdateOperation() = %v, %v", updated, err)
	}
	if unfinished, err := database.UnfinishedOperations(t.Context()); err != nil || len(unfinished) != 0 {
		t.Fatalf("terminal UnfinishedOperations() = %+v, %v", unfinished, err)
	}
	if deleted, err := database.DeleteTerminalOperationsBefore(t.Context(), now.Add(2*time.Minute)); err != nil || deleted != 1 {
		t.Fatalf("DeleteTerminalOperationsBefore() = %d, %v", deleted, err)
	}
}
