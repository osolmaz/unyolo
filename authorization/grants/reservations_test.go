package grants

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUseReservationIsStale(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		use   GrantUse
		grant Grant
		want  bool
	}{
		{name: "none", grant: Grant{Status: StatusActive}, want: false},
		{name: "already retained", use: GrantUse{State: UseRetained, UpdatedAt: now.Add(-2 * time.Minute)}, grant: Grant{Status: StatusActive}, want: false},
		{name: "terminal", use: GrantUse{State: UseReserved}, grant: Grant{Status: StatusConsumed}, want: false},
		{name: "missing time", use: GrantUse{State: UseReserved}, grant: Grant{Status: StatusActive}, want: true},
		{name: "fresh", use: GrantUse{State: UseReserved, UpdatedAt: now}, grant: Grant{Status: StatusActive}, want: false},
		{name: "stale expired", use: GrantUse{State: UseReserved, UpdatedAt: now.Add(-2 * time.Minute)}, grant: Grant{Status: StatusExpired}, want: true},
	}
	for _, test := range cases {
		if got := useReservationIsStale(test.use, test.grant, now, time.Minute); got != test.want {
			t.Fatalf("useReservationIsStale(%s) = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestStaleReservationIsRetainedAcrossExpiry(t *testing.T) {
	now := time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:                func() time.Time { return now },
		ReservationTimeout: time.Minute,
	})
	result := requestTestGrant(t, store, "stale-reservation", 2)
	approveTestGrant(t, store, result.Grant.ID)
	reserved, err := store.ReserveUse(result.Grant.ID, "stale-use", result.Grant.Operation)
	if err != nil || reserved.Grant.ReservedAt.IsZero() {
		t.Fatalf("ReserveUse() = %+v err=%v", reserved, err)
	}
	now = now.Add(2 * time.Minute)
	if err := store.reconcileDueLifecycle(); err != nil {
		t.Fatal(err)
	}
	if retained, err := store.Get(result.Grant.ID); err != nil || !retained.ReservationRetained || retained.Status != StatusActive {
		t.Fatalf("stale reservation = %+v err=%v, want retained on an active grant", retained, err)
	}
	now = result.Grant.CreatedAt.Add(10 * time.Minute)
	if err := store.reconcileDueLifecycle(); err != nil {
		t.Fatal(err)
	}
	committed, err := store.CommitUse(result.Grant.ID, "stale-use")
	if err != nil || committed.Grant.UsedCount != 1 || committed.Grant.ReservedCount != 0 || committed.Grant.ReservationRetained {
		t.Fatalf("CommitUse(expired reservation) = %+v err=%v", committed, err)
	}
}

func TestOverlappingReservationsAdvanceRecoveryClock(t *testing.T) {
	cases := []struct {
		name   string
		settle func(*Store, string, string) (UseReservation, error)
	}{
		{name: "commit", settle: func(store *Store, id, requestID string) (UseReservation, error) {
			return store.CommitUse(id, requestID)
		}},
		{name: "release", settle: func(store *Store, id, requestID string) (UseReservation, error) {
			return store.ReleaseUse(id, requestID)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assertOverlappingReservationClock(t, test.name, test.settle)
		})
	}
}

func assertOverlappingReservationClock(t *testing.T, name string, settle func(*Store, string, string) (UseReservation, error)) {
	t.Helper()
	now := time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now: func() time.Time { return now }, ReservationTimeout: 10 * time.Minute,
	})
	request := testGrantRequest("overlap-"+name, 3)
	request.Duration = time.Hour
	result, created, err := store.Request(request)
	if err != nil || !created {
		t.Fatalf("Request() = %+v created=%v err=%v", result, created, err)
	}
	approveTestGrant(t, store, result.Grant.ID)
	if _, err := store.ReserveUse(result.Grant.ID, "overlap-first", result.Grant.Operation); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	second, err := store.ReserveUse(result.Grant.ID, "overlap-second", result.Grant.Operation)
	if err != nil || !second.Grant.ReservedAt.Equal(result.Grant.CreatedAt) || second.Grant.ReservationRevision != 2 {
		t.Fatalf("second ReserveUse() = %+v err=%v", second, err)
	}
	now = now.Add(2 * time.Minute)
	settled, err := settle(store, result.Grant.ID, "overlap-first")
	if err != nil || settled.Grant.ReservedCount != 1 || !settled.Grant.ReservedAt.Equal(second.Use.UpdatedAt) {
		t.Fatalf("%s overlapping reservation = %+v err=%v", name, settled, err)
	}
	now = now.Add(7 * time.Minute)
	if err := store.reconcileDueLifecycle(); err != nil {
		t.Fatal(err)
	}
	fresh, err := store.Get(result.Grant.ID)
	if err != nil || fresh.ReservationRetained {
		t.Fatalf("fresh overlapping reservation = %+v err=%v", fresh, err)
	}
	now = now.Add(3 * time.Minute)
	if err := store.reconcileDueLifecycle(); err != nil {
		t.Fatal(err)
	}
	stale, err := store.Get(result.Grant.ID)
	if err != nil || !stale.ReservationRetained {
		t.Fatalf("stale overlapping reservation = %+v err=%v", stale, err)
	}
}

func TestRetainUseAndReleaseClearReservationState(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "retain-release", 2)
	approveTestGrant(t, store, result.Grant.ID)
	if _, err := store.ReserveUse(result.Grant.ID, "retain-release-use", result.Grant.Operation); err != nil {
		t.Fatal(err)
	}
	retained, err := store.RetainUse(result.Grant.ID, "retain-release-use")
	if err != nil || !retained.Grant.ReservationRetained {
		t.Fatalf("RetainUse() = %+v err=%v", retained, err)
	}
	released, err := store.ReleaseUse(result.Grant.ID, "retain-release-use")
	if err != nil || released.Grant.ReservedCount != 0 || released.Grant.ReservationRetained || !released.Grant.ReservedAt.IsZero() {
		t.Fatalf("ReleaseUse() = %+v err=%v", released, err)
	}
	if _, err := store.RetainUse(result.Grant.ID, "retain-release-use"); !errors.Is(err, ErrUseSettled) {
		t.Fatalf("RetainUse(settled reservation) error=%v, want ErrUseSettled", err)
	}
}

func TestRetainedReservationPreservesRemainingGrantAuthority(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "retained-overlay", 2)
	approveTestGrant(t, store, result.Grant.ID)
	if _, err := store.ReserveUse(result.Grant.ID, "retained-overlay-use", result.Grant.Operation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RetainUse(result.Grant.ID, "retained-overlay-use"); err != nil {
		t.Fatal(err)
	}
	if active, err := store.ActivePolicyGrants(); err != nil || len(active) != 1 || active[0].UsesLeft != 1 {
		t.Fatalf("ActivePolicyGrants(retained) = %+v err=%v, want one remaining use", active, err)
	}
	second, err := store.ReserveUse(result.Grant.ID, "retained-overlay-second", result.Grant.Operation)
	if err != nil || second.Grant.ReservedCount != 2 {
		t.Fatalf("ReserveUse(second) = %+v err=%v", second, err)
	}
	if _, err := store.ReleaseUse(result.Grant.ID, "retained-overlay-second"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseUse(result.Grant.ID, "retained-overlay-use"); err != nil {
		t.Fatal(err)
	}
	if active, err := store.ActivePolicyGrants(); err != nil || len(active) != 1 {
		t.Fatalf("ActivePolicyGrants(released) = %+v err=%v, want restored grant", active, err)
	}
}

func TestRevokedReservationCanBeSettled(t *testing.T) {
	now := time.Date(2026, 7, 10, 4, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:                func() time.Time { return now },
		ReservationTimeout: time.Minute,
	})
	committed := approvedReservedGrant(t, store, "revoked-commit")
	if _, err := store.Revoke(committed.Grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	settled, err := store.CommitUse(committed.Grant.ID, committed.Use.RequestID)
	if err != nil || settled.Grant.Status != StatusRevoked || settled.Grant.UsedCount != 1 || settled.Grant.ReservedCount != 0 {
		t.Fatalf("CommitUse(revoked) = %+v err=%v", settled, err)
	}

	retained := approvedReservedGrant(t, store, "revoked-retain")
	if _, err := store.Revoke(retained.Grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if err := store.reconcileDueLifecycle(); err != nil {
		t.Fatal(err)
	}
	if current, err := store.Get(retained.Grant.ID); err != nil || !current.ReservationRetained {
		t.Fatalf("revoked stale reservation = %+v err=%v, want retained", current, err)
	}
	if _, err := store.ReleaseUse(retained.Grant.ID, retained.Use.RequestID); err != nil {
		t.Fatal(err)
	}
}

func approvedReservedGrant(t *testing.T, store *Store, requestID string) UseReservation {
	t.Helper()
	result := requestTestGrant(t, store, requestID, 1)
	approved := approveTestGrant(t, store, result.Grant.ID)
	reserved, err := store.ReserveUse(approved.ID, requestID+"-use", approved.Operation)
	if err != nil {
		t.Fatal(err)
	}
	return reserved
}
