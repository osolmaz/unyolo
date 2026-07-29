package grants

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
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
	if _, err := store.GetUse("missing-grant", "operation-1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing grant use error = %v", err)
	}
	if _, err := store.GetUse(approved.ID, "missing-use"); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("missing use error = %v", err)
	}
	if _, err := store.GetUse(other.Grant.ID, "operation-1"); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("mismatched use owner error = %v", err)
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

func TestLoadedGrantUseValidationRejectsMalformedRecords(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	grant := Grant{ID: "grant-1", Operation: "repo.write"}
	valid := GrantUse{GrantID: grant.ID, RequestID: "request-1", Operation: grant.Operation,
		State: UseReserved, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if !validLoadedUse(valid, grant) {
		t.Fatal("valid use was rejected")
	}
	tests := map[string]func(*GrantUse){
		"missing identity": func(use *GrantUse) { use.RequestID = "" },
		"wrong operation":  func(use *GrantUse) { use.Operation = "repo.delete" },
		"invalid state":    func(use *GrantUse) { use.State = "invalid" },
		"invalid revision": func(use *GrantUse) { use.Revision = 0 },
		"missing creation": func(use *GrantUse) { use.CreatedAt = time.Time{} },
		"time reversal":    func(use *GrantUse) { use.UpdatedAt = now.Add(-time.Second) },
		"false settlement": func(use *GrantUse) { use.SettledAt = now },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := valid
			mutate(&changed)
			if validLoadedUse(changed, grant) {
				t.Fatal("malformed use was accepted")
			}
		})
	}
	committed := valid
	committed.State = UseCommitted
	committed.UpdatedAt = now.Add(time.Second)
	committed.SettledAt = committed.UpdatedAt
	if !validLoadedUse(committed, grant) {
		t.Fatal("committed use was rejected")
	}
	if validateLoadedUses([]Grant{grant}, []GrantUse{valid, valid}) == nil {
		t.Fatal("duplicate request identity was accepted")
	}
}

func TestGrantUseInputAndAggregateValidation(t *testing.T) {
	firstIdentity, err := NewUseRequestIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secondIdentity, err := NewUseRequestIdentity()
	if err != nil || firstIdentity == secondIdentity || !validUseIdentity("grant", firstIdentity, "repo.write") {
		t.Fatalf("native identities = %q/%q, %v", firstIdentity, secondIdentity, err)
	}
	if _, err := DeriveUseRequestID("", "request"); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("empty grant identity error = %v", err)
	}
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	if _, err := store.ReserveUse("", "request", "repo.write"); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("invalid reservation error = %v", err)
	}
	if _, err := store.CommitUse("", "request"); !errors.Is(err, ErrUseIdentityConflict) {
		t.Fatalf("invalid settlement error = %v", err)
	}
	if _, err := store.ListUses("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing grant list error = %v", err)
	}
	if validUseIdentity("grant", strings.Repeat("x", 129), "repo.write") || validUseIdentity("grant", "bad request", "repo.write") {
		t.Fatal("invalid request identity was accepted")
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	uses := []GrantUse{
		{GrantID: "grant-1", RequestID: "reserved", Operation: "repo.write", State: UseReserved, Revision: 1, CreatedAt: now, UpdatedAt: now},
		{GrantID: "grant-1", RequestID: "committed", Operation: "repo.write", State: UseCommitted, Revision: 2, CreatedAt: now, UpdatedAt: now.Add(time.Second), SettledAt: now.Add(time.Second)},
		{GrantID: "grant-1", RequestID: "released", Operation: "repo.write", State: UseReleased, Revision: 2, CreatedAt: now, UpdatedAt: now.Add(2 * time.Second), SettledAt: now.Add(2 * time.Second)},
		{GrantID: "grant-1", RequestID: "retained", Operation: "repo.write", State: UseRetained, Revision: 1, CreatedAt: now, UpdatedAt: now.Add(3 * time.Second)},
	}
	grant := aggregateGrantUses(Grant{ID: "grant-1", Operation: "repo.write"}, uses)
	grant.UseRevision = grant.UsedCount
	grant.ReservationRevision = useRevisionTotal(grant.ID, uses)
	if err := validateLoadedUses([]Grant{grant}, uses); err != nil {
		t.Fatalf("valid aggregate error = %v", err)
	}
	grant.ReservationRevision++
	if !errors.Is(validateLoadedUses([]Grant{grant}, uses), ErrUnsupportedState) {
		t.Fatal("invalid reservation revision was accepted")
	}
	if !errors.Is(validateLoadedUses(nil, uses), ErrUnsupportedState) {
		t.Fatal("use without owning grant was accepted")
	}
}

func TestGrantAndUseLifecycleDeadlines(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	pending := Grant{Status: StatusPending, PendingExpiresAt: now.Add(time.Minute)}
	active := Grant{Status: StatusActive, ExpiresAt: now.Add(2 * time.Minute)}
	if got := grantLifecycleDeadline(pending); got != pending.PendingExpiresAt {
		t.Fatalf("pending deadline = %v", got)
	}
	if got := grantLifecycleDeadline(active); got != active.ExpiresAt {
		t.Fatalf("active deadline = %v", got)
	}
	if got := grantLifecycleDeadline(Grant{Status: StatusRevoked}); !got.IsZero() {
		t.Fatalf("revoked deadline = %v", got)
	}
	if got := earlierDeadline(active.ExpiresAt, pending.PendingExpiresAt); got != pending.PendingExpiresAt {
		t.Fatalf("earlier deadline = %v", got)
	}
	if got := earlierDeadline(pending.PendingExpiresAt, time.Time{}); got != pending.PendingExpiresAt {
		t.Fatalf("zero candidate changed deadline = %v", got)
	}

	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{ReservationTimeout: time.Minute})
	reserved := GrantUse{State: UseReserved, UpdatedAt: now}
	if got := store.useLifecycleDeadline(reserved, active, now); got != now.Add(time.Minute) {
		t.Fatalf("reservation deadline = %v", got)
	}
	if got := store.useLifecycleDeadline(GrantUse{State: UseCommitted}, active, now); !got.IsZero() {
		t.Fatalf("settled use deadline = %v", got)
	}
	stale := reserved
	stale.UpdatedAt = now.Add(-2 * time.Minute)
	if got := store.useLifecycleDeadline(stale, active, now); got != now {
		t.Fatalf("stale reservation deadline = %v", got)
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
