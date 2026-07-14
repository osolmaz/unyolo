package state

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/plandigest"
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
	if count, err := database.CountOperations(t.Context()); err != nil || count != 1 {
		t.Fatalf("CountOperations() = %d, %v", count, err)
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

func TestOperationPagesSortFractionalSecondsChronologically(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	base := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	for _, record := range []OperationRecord{
		testOperationRecord("op_older", base.Add(100*time.Millisecond)),
		testOperationRecord("op_newer", base.Add(110*time.Millisecond)),
	} {
		if err := database.InsertOperation(t.Context(), record); err != nil {
			t.Fatal(err)
		}
	}
	page, err := database.OperationsForClient(t.Context(), OperationListOptions{ClientID: "agent", Limit: 1})
	if err != nil || len(page) != 1 || page[0].ID != "op_newer" {
		t.Fatalf("first page = %+v, %v", page, err)
	}
	page, err = database.OperationsForClient(t.Context(), OperationListOptions{ClientID: "agent", Cursor: "op_newer", Limit: 2})
	if err != nil || len(page) != 1 || page[0].ID != "op_older" {
		t.Fatalf("second page = %+v, %v", page, err)
	}
}

func testOperationRecord(id string, createdAt time.Time) OperationRecord {
	return OperationRecord{
		ID: id, APIVersion: "brokerkit.io/agent/v1", Broker: "test", ClientID: "agent", IdempotencyKey: id,
		Operation: "repo.read", TargetJSON: []byte(`{}`), ArgumentsJSON: []byte(`{}`), Reason: "read",
		State: "pending", Revision: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		PresentationJSON: []byte(`{"title":"Read"}`),
	}
}

func TestInsertOperationWithPlanIsAtomic(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 9, 0, 0, 0, time.UTC)
	canonical := []byte(`{"api_version":"hf-broker.io/plan/v1","operation":"repo.delete"}`)
	plan := PlanRecord{Digest: plandigest.Digest(canonical), SchemaName: "hf-broker.io/plan/v1", Canonical: canonical, CreatedAt: now}
	record := OperationRecord{ID: "op_plan", APIVersion: "brokerkit.io/agent/v1", Broker: "hf-broker", ClientID: "agent",
		IdempotencyKey: "plan", Operation: "repo.delete", TargetJSON: []byte(`{}`), ArgumentsJSON: []byte(`{}`), Reason: "delete",
		State: "pending", Revision: 1, CreatedAt: now, UpdatedAt: now, PresentationJSON: []byte(`{"title":"Delete"}`), PlanDigest: plan.Digest}
	if err := database.InsertOperationWithPlan(t.Context(), record, plan); err != nil {
		t.Fatal(err)
	}
	stored, err := database.OperationByID(t.Context(), record.ID)
	if err != nil || stored.PlanDigest != plan.Digest {
		t.Fatalf("stored operation = %+v, %v", stored, err)
	}

	bad := record
	bad.ID, bad.IdempotencyKey, bad.PlanDigest = "op_bad", "bad", strings.Repeat("0", 64)
	if err := database.InsertOperationWithPlan(t.Context(), bad, plan); err == nil {
		t.Fatal("mismatched plan digest accepted")
	}
	if _, err := database.OperationByID(t.Context(), bad.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("operation survived rollback: %v", err)
	}
}

func TestUpdateOperationWithPlanIsAtomic(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 9, 30, 0, 0, time.UTC)
	record := OperationRecord{ID: "op_bind", APIVersion: "brokerkit.io/agent/v1", Broker: "hf-broker", ClientID: "agent",
		IdempotencyKey: "bind", Operation: "repo.delete", TargetJSON: []byte(`{}`), ArgumentsJSON: []byte(`{}`), Reason: "delete",
		State: "pending", Revision: 1, CreatedAt: now, UpdatedAt: now, PresentationJSON: []byte(`{"title":"Delete"}`)}
	if err := database.InsertOperation(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	canonical := []byte(`{"api_version":"hf-broker.io/plan/v1","operation":"repo.delete"}`)
	plan := PlanRecord{Digest: plandigest.Digest(canonical), SchemaName: "hf-broker.io/plan/v1", Canonical: canonical, CreatedAt: now}
	record.PlanDigest, record.ApprovalID, record.Revision = plan.Digest, "grant-1", 2
	if updated, err := database.UpdateOperationWithPlan(t.Context(), record, 1, plan); err != nil || !updated {
		t.Fatalf("UpdateOperationWithPlan() = %v, %v", updated, err)
	}
	stored, err := database.OperationByID(t.Context(), record.ID)
	if err != nil || stored.PlanDigest != plan.Digest || stored.ApprovalID != "grant-1" {
		t.Fatalf("bound operation = %+v, %v", stored, err)
	}
}

func TestOperationRepositoryRejectsCorruptTimestamps(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 1, 0, 0, 0, time.UTC)
	record := OperationRecord{ID: "op", APIVersion: "brokerkit.io/agent/v1", Broker: "test", ClientID: "client",
		IdempotencyKey: "key", Operation: "test", TargetJSON: []byte(`{}`), ArgumentsJSON: []byte(`{}`), State: "pending",
		Revision: 1, CreatedAt: now, UpdatedAt: now, PresentationJSON: []byte(`{}`)}
	if err := database.InsertOperation(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SQL().ExecContext(t.Context(), "UPDATE operations SET created_at = 'invalid' WHERE id = 'op'"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.OperationByID(t.Context(), "op"); err == nil {
		t.Fatal("OperationByID() accepted a corrupt required timestamp")
	}
	if _, err := database.SQL().ExecContext(t.Context(), "UPDATE operations SET created_at = ?, terminal_at = 'invalid' WHERE id = 'op'", formatTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.OperationByID(t.Context(), "op"); err == nil {
		t.Fatal("OperationByID() accepted a corrupt optional timestamp")
	}
}
