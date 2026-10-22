package state

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/internal/storage/state/internal/dbsql"
	"github.com/osolmaz/unyolo/operation/digest"
)

func testIntPointer(value int) *int { return &value }

func TestGrantSnapshotRejectsStaleWriter(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	empty, err := database.GrantSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
	created := empty
	created.Grants = append(created.Grants, GrantRecord{ID: "grant-1", Client: "bob",
		ClientRequestID: "request-1", Operation: "repo.create", TargetJSON: []byte(`{"kind":"hf","fields":{"name":["model/acme/demo"]}}`),
		AttrsJSON: []byte(`{}`), MetadataJSON: []byte(`{}`), Reason: "test", Status: "pending", Revision: 1,
		CreatedAt: now, PendingExpiresAt: now.Add(time.Minute), Duration: time.Minute, RequestedDuration: time.Minute,
		PendingTimeout: time.Minute, MaxUses: testIntPointer(1), RequestedMaxUses: testIntPointer(1)})
	if err := database.SaveGrantSnapshot(t.Context(), empty, created); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveGrantSnapshot(t.Context(), empty, created); !errors.Is(err, ErrGrantStateConflict) {
		t.Fatalf("stale SaveGrantSnapshot() error = %v", err)
	}
	stored, err := database.GrantSnapshot(t.Context())
	if err != nil || len(stored.Grants) != 1 || stored.Grants[0].ID != "grant-1" {
		t.Fatalf("GrantSnapshot() = %+v, %v", stored, err)
	}
}

func TestGrantSnapshotPersistsCompleteLifecycle(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	empty, err := database.GrantSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)
	canonical := []byte(`{"operation":"repo.create","schema":"hf/v1"}`)
	plan := PlanRecord{Digest: plandigest.Digest(canonical), SchemaName: "hf/v1", Canonical: canonical, CreatedAt: now}
	created := GrantSnapshot{
		Grants: []GrantRecord{{
			ID: "grant-1", Client: "bob", ClientRequestID: "request-1",
			Operation: "repo.create", TargetJSON: []byte(`{"kind":"hf"}`), AttrsJSON: []byte(`{}`), MetadataJSON: []byte(`{}`),
			PlanDigest: plan.Digest, Reason: "test", Status: "pending", Revision: 1, CreatedAt: now,
			PendingExpiresAt: now.Add(time.Minute), Duration: 5 * time.Minute, RequestedDuration: 10 * time.Minute,
			PendingTimeout: time.Minute, MaxUses: testIntPointer(1_000_000), RequestedMaxUses: testIntPointer(1_000_000),
		}},
		Events: []GrantLifecycleRecord{
			{Sequence: 1, Cursor: "cursor-1", GrantID: "grant-1", Kind: "requested", Revision: 1, OccurredAt: now, PayloadJSON: []byte(`{}`)},
			{Sequence: 2, Cursor: "cursor-2", GrantID: "grant-1", Kind: "notified", Revision: 1, OccurredAt: now.Add(time.Second), PayloadJSON: []byte(`{}`)},
		},
		Decisions: []GrantDecisionRecord{{Scope: "grant-1/approve/key-1", RequestID: "grant-1", Action: "approve",
			IdempotencyKey: "key-1", CommandHash: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ", ResultJSON: []byte(`{}`),
			PreviousJSON: []byte(`{}`), EventCursor: "cursor-2", CommittedAt: now.Add(2 * time.Second)}},
	}
	if err := database.SaveGrantSnapshotWithPlan(t.Context(), empty, created, plan); err != nil {
		t.Fatal(err)
	}
	stored, err := database.GrantSnapshot(t.Context())
	if err != nil || len(stored.Grants) != 1 || len(stored.Events) != 2 || len(stored.Decisions) != 1 {
		t.Fatalf("GrantSnapshot() = %+v, %v", stored, err)
	}
	if stored.Grants[0].PlanDigest != plan.Digest || *stored.Grants[0].MaxUses != 1_000_000 || *stored.Grants[0].RequestedMaxUses != 1_000_000 {
		t.Fatalf("stored grant = %+v", stored.Grants[0])
	}

	updated := stored
	updated.Grants = append([]GrantRecord(nil), stored.Grants...)
	grant := &updated.Grants[0]
	grant.Status, grant.Revision = "active", 2
	grant.ExpiresAt, grant.DecidedAt = now.Add(5*time.Minute), now.Add(3*time.Second)
	grant.DecidedBy, grant.DecidedOnBehalfOf = "onur", "operator"
	grant.UsedAt, grant.UsedCount, grant.UseRevision = now.Add(4*time.Second), 1, 1
	grant.ReservedAt, grant.ReservedCount = now.Add(4*time.Second), 1
	grant.ReservationRetained, grant.ReservationRevision = true, 1
	grant.ExpiredFrom = "pending"
	updated.Events = []GrantLifecycleRecord{
		stored.Events[1],
		{Sequence: 3, Cursor: "cursor-3", GrantID: "grant-1", Kind: "approved", Revision: 2, OccurredAt: now.Add(3 * time.Second), PayloadJSON: []byte(`{}`)},
	}
	updated.Decisions = append(append([]GrantDecisionRecord(nil), stored.Decisions...), GrantDecisionRecord{
		Scope: "grant-1/consume/key-2", RequestID: "grant-1", Action: "consume", IdempotencyKey: "key-2",
		CommandHash: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPR", ResultJSON: []byte(`{}`), PreviousJSON: []byte(`{}`),
		EventCursor: "cursor-3", CommittedAt: now.Add(4 * time.Second),
	})
	if err := database.SaveGrantSnapshot(t.Context(), stored, updated); err != nil {
		t.Fatal(err)
	}
	reloaded, err := database.GrantSnapshot(t.Context())
	if err != nil || reloaded.Grants[0].Status != "active" || len(reloaded.Events) != 2 || reloaded.Events[0].Sequence != 2 ||
		len(reloaded.Decisions) != 2 {
		t.Fatalf("updated GrantSnapshot() = %+v, %v", reloaded, err)
	}
}

func TestGrantSnapshotRejectsDestructiveAndInvalidTransitions(t *testing.T) {
	grant := GrantRecord{ID: "grant-1"}
	event := GrantLifecycleRecord{Sequence: 1, Cursor: "one"}
	decision := GrantDecisionRecord{Scope: "scope"}
	base := GrantSnapshot{Grants: []GrantRecord{grant}, Events: []GrantLifecycleRecord{event}, Decisions: []GrantDecisionRecord{decision}}
	tests := []struct {
		name  string
		after GrantSnapshot
	}{
		{name: "grant deletion", after: GrantSnapshot{Events: base.Events, Decisions: base.Decisions}},
		{name: "event mutation", after: GrantSnapshot{Grants: base.Grants, Events: []GrantLifecycleRecord{{Sequence: 1, Cursor: "changed"}}, Decisions: base.Decisions}},
		{name: "decision mutation", after: GrantSnapshot{Grants: base.Grants, Events: base.Events, Decisions: []GrantDecisionRecord{{Scope: "scope", Action: "changed"}}}},
		{name: "decision deletion", after: GrantSnapshot{Grants: base.Grants, Events: base.Events}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateGrantSnapshotTransition(base, test.after); err == nil {
				t.Fatal("transition unexpectedly accepted")
			}
		})
	}
}

func TestGrantSnapshotRejectsInvalidAppendedRecords(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	empty, err := database.GrantSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 13, 4, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*GrantSnapshot){
		"event sequence overflow": func(snapshot *GrantSnapshot) {
			snapshot.Events = []GrantLifecycleRecord{{Sequence: ^uint64(0), Cursor: "cursor", GrantID: "grant", Kind: "test", Revision: 1, OccurredAt: now, PayloadJSON: []byte(`{}`)}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			after := empty
			mutate(&after)
			if err := database.SaveGrantSnapshot(t.Context(), empty, after); err == nil {
				t.Fatal("SaveGrantSnapshot() accepted invalid record")
			}
		})
	}
}

func TestDecodeGrantRecordRejectsCorruptTimestamps(t *testing.T) {
	now := formatTime(time.Date(2026, 7, 13, 5, 0, 0, 0, time.UTC))
	valid := dbsql.Grant{CreatedAt: now, PendingExpiresAt: now}
	tests := []struct {
		name   string
		mutate func(*dbsql.Grant)
	}{
		{name: "required", mutate: func(row *dbsql.Grant) { row.CreatedAt = "invalid" }},
		{name: "optional", mutate: func(row *dbsql.Grant) { row.ExpiresAt = sql.NullString{String: "invalid", Valid: true} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			row := valid
			test.mutate(&row)
			if _, err := decodeGrantRecord(row); err == nil {
				t.Fatal("decodeGrantRecord() accepted a corrupt timestamp")
			}
		})
	}
}

func TestSaveGrantSnapshotWithPlanRejectsInvalidPlanAtomically(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	empty, err := database.GrantSnapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveGrantSnapshotWithPlan(t.Context(), empty, empty, PlanRecord{}); err == nil {
		t.Fatal("SaveGrantSnapshotWithPlan() accepted an invalid plan")
	}
	if count, err := database.Queries().CountPlans(t.Context()); err != nil || count != 0 {
		t.Fatalf("plans after rollback = %d, %v", count, err)
	}
}

func TestGrantSnapshotFailsAfterDatabaseClose(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := database.GrantSnapshot(t.Context()); err == nil {
		t.Fatal("GrantSnapshot() succeeded after Close()")
	}
	if err := database.SaveGrantSnapshot(t.Context(), GrantSnapshot{}, GrantSnapshot{}); err == nil {
		t.Fatal("SaveGrantSnapshot() succeeded after Close()")
	}
}

func TestGrantSnapshotRejectsCorruptLifecycleEvent(t *testing.T) {
	database, err := Open(t.Context(), t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	_, err = database.SQL().ExecContext(t.Context(), `INSERT INTO lifecycle_events
		(sequence, cursor, subject_kind, subject_id, kind, revision, occurred_at, payload_json)
		VALUES (1, 'cursor', 'grant', 'grant', 'requested', 1, 'invalid', '{}')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.GrantSnapshot(t.Context()); err == nil {
		t.Fatal("GrantSnapshot() accepted a corrupt lifecycle event")
	}
}
