package grants

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestGrantUseIdentityIsIdempotentAndConflictSafe(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "identity", 2)
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.ReserveUse(approved.ID, "operation-1", approved.Operation)
	if err != nil || !first.Acquired || first.Use.State != UseReserved || first.Grant.ReservedCount != 1 {
		t.Fatalf("first ReserveUse() = %+v, %v", first, err)
	}
	replay, err := store.ReserveUse(approved.ID, "operation-1", approved.Operation)
	if err != nil || replay.Acquired || replay.Use.Revision != first.Use.Revision || replay.Grant.ReservedCount != 1 {
		t.Fatalf("replayed ReserveUse() = %+v, %v", replay, err)
	}
	if _, err := store.ReserveUse(approved.ID, "operation-1", "different.operation"); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("conflicting operation error = %v", err)
	}

	other := requestTestGrant(t, store, "other-grant", 2)
	if _, err := store.Approve(other.Grant.ID, other.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(other.Grant.ID, "operation-1", other.Grant.Operation); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("conflicting grant error = %v", err)
	}

	committed, err := store.CommitUse(approved.ID, "operation-1")
	if err != nil || committed.Use.State != UseCommitted || committed.Grant.UsedCount != 1 {
		t.Fatalf("CommitUse() = %+v, %v", committed, err)
	}
	committedReplay, err := store.CommitUse(approved.ID, "operation-1")
	if err != nil || committedReplay.Use.Revision != committed.Use.Revision || committedReplay.Grant.UsedCount != 1 {
		t.Fatalf("replayed CommitUse() = %+v, %v", committedReplay, err)
	}
	if _, err := store.ReleaseUse(approved.ID, "operation-1"); !errors.Is(err, ErrUseSettled) {
		t.Fatalf("conflicting settlement error = %v", err)
	}
}

func TestReleasedGrantUseCanBeSafelyReacquired(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "released-retry", 1)
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := store.ReserveUse(approved.ID, "native-request", approved.Operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseUse(approved.ID, reserved.Use.RequestID); err != nil {
		t.Fatal(err)
	}
	reacquired, err := store.ReserveUse(approved.ID, reserved.Use.RequestID, approved.Operation)
	if err != nil || !reacquired.Acquired || reacquired.Use.State != UseReserved || reacquired.Use.Revision != 3 || reacquired.Grant.ReservedCount != 1 {
		t.Fatalf("reacquired ReserveUse() = %+v, %v", reacquired, err)
	}
}

func TestConcurrentGrantUseReservationsStopAtFiniteBudget(t *testing.T) {
	const limit = 8
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "concurrent-budget", limit)
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	var lock sync.Mutex
	created := 0
	for index := range limit * 3 {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			reservation, reserveErr := store.ReserveUse(approved.ID, fmt.Sprintf("operation-%02d", index), approved.Operation)
			if reserveErr == nil && reservation.Acquired {
				lock.Lock()
				created++
				lock.Unlock()
				return
			}
			if reserveErr != nil && !errors.Is(reserveErr, ErrNotActive) {
				t.Errorf("ReserveUse(%d) error = %v", index, reserveErr)
			}
		}(index)
	}
	wait.Wait()
	grant, err := store.Get(approved.ID)
	if err != nil || created != limit || grant.ReservedCount != limit || grant.UsedCount != 0 {
		t.Fatalf("created=%d grant=%+v err=%v", created, grant, err)
	}
}

func TestRestartSettlesOwningReservationAfterEarlierUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	store := New(path, Options{})
	result := requestTestGrant(t, store, "restart-owner", 3)
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(approved.ID, "operation-1", approved.Operation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(approved.ID, "operation-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(approved.ID, "operation-2", approved.Operation); err != nil {
		t.Fatal(err)
	}

	restarted := New(path, Options{Now: func() time.Time { return time.Now() }})
	owning, err := restarted.GetUse(approved.ID, "operation-2")
	if err != nil || owning.Use.State != UseReserved || owning.Grant.UsedCount != 1 || owning.Grant.ReservedCount != 1 {
		t.Fatalf("restarted GetUse() = %+v, %v", owning, err)
	}
	settled, err := restarted.CommitUse(approved.ID, "operation-2")
	if err != nil || settled.Grant.UsedCount != 2 || settled.Grant.ReservedCount != 0 {
		t.Fatalf("restarted CommitUse() = %+v, %v", settled, err)
	}
	first, err := restarted.GetUse(approved.ID, "operation-1")
	if err != nil || first.Use.State != UseCommitted || first.Use.Revision != 2 {
		t.Fatalf("first use changed during second settlement: %+v, %v", first, err)
	}
}
