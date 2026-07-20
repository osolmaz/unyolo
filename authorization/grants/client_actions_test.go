package grants

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestClientGrantActionsEnforceOwnerAndStateAtomically(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	pending := requestTestGrant(t, store, "client-cancel", 1)
	if _, err := store.CancelForClient(pending.Grant.ID, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("CancelForClient(other) error = %v", err)
	}
	canceled, err := store.CancelForClient(pending.Grant.ID, "bob")
	if err != nil || canceled.Status != StatusCanceled {
		t.Fatalf("CancelForClient() = %+v, %v", canceled, err)
	}
	if _, err := store.CancelForClient(pending.Grant.ID, "bob"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("CancelForClient(terminal) error = %v", err)
	}

	activeRequest := requestTestGrant(t, store, "client-revoke", 1)
	active, err := store.Approve(activeRequest.Grant.ID, activeRequest.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RevokeForClient(active.ID, "other"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("RevokeForClient(other) error = %v", err)
	}
	revoked, err := store.RevokeForClient(active.ID, "bob")
	if err != nil || revoked.Status != StatusRevoked || revoked.DecidedBy != "bob" {
		t.Fatalf("RevokeForClient() = %+v, %v", revoked, err)
	}
	if _, err := store.RevokeForClient(active.ID, "bob"); !errors.Is(err, ErrNotActive) {
		t.Fatalf("RevokeForClient(terminal) error = %v", err)
	}
}
