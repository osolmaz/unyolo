package state

import (
	"errors"
	"testing"
	"time"
)

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
	created.Grants = append(created.Grants, GrantRecord{ID: "grant-1", DecisionTokenVerifier: "verifier", Client: "bob",
		ClientRequestID: "request-1", Operation: "repo.create", TargetJSON: []byte(`{"kind":"hf","fields":{"name":["model/acme/demo"]}}`),
		AttrsJSON: []byte(`{}`), MetadataJSON: []byte(`{}`), Reason: "test", Status: "pending", Revision: 1,
		CreatedAt: now, PendingExpiresAt: now.Add(time.Minute), Duration: time.Minute, RequestedDuration: time.Minute,
		PendingTimeout: time.Minute, MaxUses: 1, RequestedMaxUses: 1})
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
