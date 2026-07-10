package grants

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/notify"
)

func TestNotificationClaimAndDeliveryLifecycle(t *testing.T) {
	now := time.Date(2026, 7, 10, 1, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	result := requestTestGrant(t, store, "notification-lifecycle", 1)

	claim := claimNotificationOnce(t, store, result.Grant.ID)
	state, err := os.ReadFile(store.path) // #nosec G304 -- test reads its own temp state file.
	if err != nil {
		t.Fatal(err)
	}
	assertNoRawDecisionToken(t, string(state), claim.DecisionToken)
	ref := notify.MessageRef{Kind: "telegram", ChatID: 42, MessageID: 7, Text: "request"}
	setClaimedNotification(t, store, result.Grant.ID, claim.Grant.NotificationClaimedAt, ref)
	assertNotifiedRetryHasNoToken(t, store, "notification-lifecycle")

	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); !errors.Is(err, ErrInvalidDecisionToken) {
		t.Fatalf("Approve(pre-claim token) error = %v, want ErrInvalidDecisionToken", err)
	}
	approved, err := store.Approve(result.Grant.ID, claim.DecisionToken, "operator")
	if err != nil || approved.Status != StatusActive {
		t.Fatalf("Approve() = %+v err=%v", approved, err)
	}
	assertSingleDueUpdate(t, store, StatusUpdateLifecycle, StatusActive, string(StatusActive))
	if err := store.MarkNotificationStatus(result.Grant.ID, string(StatusActive)); err != nil {
		t.Fatal(err)
	}
	assertNoDueUpdates(t, store)

	if _, err := store.Revoke(result.Grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	assertSingleDueUpdate(t, store, StatusUpdateLifecycle, StatusRevoked, string(StatusRevoked))
}

func TestNotificationClaimRecoveryAndConditionalCancel(t *testing.T) {
	now := time.Date(2026, 7, 10, 2, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	result := requestTestGrant(t, store, "claim-recovery", 1)
	assertZeroClaimCannotMutate(t, store, result.Grant.ID)
	first := claimNotification(t, store, result.Grant.ID)
	now = now.Add(2 * time.Minute)
	second := claimNotification(t, store, result.Grant.ID)
	if second.Grant.NotificationClaimedAt.Equal(first.Grant.NotificationClaimedAt) || second.DecisionToken == first.DecisionToken {
		t.Fatalf("reclaimed = %+v, want a new claim and token after %+v", second, first)
	}
	if _, canceled, err := store.CancelIfNotificationClaimed(result.Grant.ID, first.Grant.NotificationClaimedAt); err != nil || canceled {
		t.Fatalf("stale cancel canceled=%v err=%v", canceled, err)
	}
	canceledGrant, canceled, err := store.CancelIfNotificationClaimed(result.Grant.ID, second.Grant.NotificationClaimedAt)
	if err != nil || !canceled || canceledGrant.Status != StatusCanceled {
		t.Fatalf("current cancel = %+v canceled=%v err=%v", canceledGrant, canceled, err)
	}
}

func TestNotificationClaimHonorsOriginalLease(t *testing.T) {
	now := time.Date(2026, 7, 10, 2, 30, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	request := testGrantRequest("claim-lease", 1)
	request.PendingTimeout = 20 * time.Minute
	result, created, err := store.Request(request)
	if err != nil || !created {
		t.Fatalf("Request() = %+v created=%v err=%v", result, created, err)
	}
	first, claimed, err := store.ClaimNotification(result.Grant.ID, 10*time.Minute)
	if err != nil || !claimed || !first.Grant.NotificationClaimUntil.Equal(now.Add(10*time.Minute)) {
		t.Fatalf("first claim = %+v claimed=%v err=%v", first, claimed, err)
	}
	now = now.Add(2 * time.Minute)
	if _, claimed, err := store.ClaimNotification(result.Grant.ID, time.Minute); err != nil || claimed {
		t.Fatalf("shorter competing lease claimed=%v err=%v", claimed, err)
	}
	now = now.Add(8 * time.Minute)
	if _, claimed, err := store.ClaimNotification(result.Grant.ID, time.Minute); err != nil || !claimed {
		t.Fatalf("expired original lease claimed=%v err=%v", claimed, err)
	}
}

func TestCancelPendingGrantAndIgnoreTerminalGrant(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "cancel", 1)
	if err := store.Cancel(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	canceled, err := store.Get(result.Grant.ID)
	if err != nil || canceled.Status != StatusCanceled || canceled.DecidedAt.IsZero() {
		t.Fatalf("Get(canceled) = %+v err=%v", canceled, err)
	}
	if err := store.Cancel(result.Grant.ID); err != nil {
		t.Fatalf("Cancel(terminal) error = %v", err)
	}
	if err := store.Cancel("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Cancel(missing) error = %v, want ErrNotFound", err)
	}
}

func TestNormalizeLoadedReservation(t *testing.T) {
	now := time.Now()
	grant := Grant{ReservedCount: -1, ReservedAt: now, ReservationRetained: true}
	if !normalizeLoadedReservation(&grant) || grant.ReservedCount != 0 || !grant.ReservedAt.IsZero() || grant.ReservationRetained {
		t.Fatalf("normalizeLoadedReservation(negative) = %+v", grant)
	}
	active := Grant{ReservedCount: 1, ReservedAt: now, ReservationRetained: true}
	if normalizeLoadedReservation(&active) || active.ReservedCount != 1 || !active.ReservationRetained {
		t.Fatalf("normalizeLoadedReservation(active) changed %+v", active)
	}
	empty := Grant{}
	if normalizeLoadedReservation(&empty) {
		t.Fatal("normalizeLoadedReservation(empty) changed clean grant")
	}
}

func TestReservationIsStale(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name  string
		grant Grant
		want  bool
	}{
		{name: "none", grant: Grant{Status: StatusActive}, want: false},
		{name: "already retained", grant: Grant{Status: StatusActive, ReservedCount: 1, ReservationRetained: true}, want: false},
		{name: "terminal", grant: Grant{Status: StatusConsumed, ReservedCount: 1}, want: false},
		{name: "missing time", grant: Grant{Status: StatusActive, ReservedCount: 1}, want: true},
		{name: "fresh", grant: Grant{Status: StatusActive, ReservedCount: 1, ReservedAt: now}, want: false},
		{name: "stale expired", grant: Grant{Status: StatusExpired, ReservedCount: 1, ReservedAt: now.Add(-2 * time.Minute)}, want: true},
	}
	for _, test := range cases {
		if got := reservationIsStale(test.grant, now, time.Minute); got != test.want {
			t.Fatalf("reservationIsStale(%s) = %v, want %v", test.name, got, test.want)
		}
	}
}

func assertZeroClaimCannotMutate(t *testing.T, store *Store, id string) {
	t.Helper()
	if _, canceled, err := store.CancelIfNotificationClaimed(id, time.Time{}); err != nil || canceled {
		t.Fatalf("zero-claim cancel canceled=%v err=%v", canceled, err)
	}
	if _, recorded, err := store.SetNotificationIfClaimed(id, time.Time{}, notify.MessageRef{MessageID: 1}); err != nil || recorded {
		t.Fatalf("zero-claim notification recorded=%v err=%v", recorded, err)
	}
}

func claimNotificationOnce(t *testing.T, store *Store, id string) NotificationClaim {
	t.Helper()
	if _, claimed, err := store.ClaimNotification(id, 0); err == nil || claimed {
		t.Fatalf("ClaimNotification(zero lease) claimed=%v err=%v, want validation error", claimed, err)
	}
	claim := claimNotification(t, store, id)
	if _, claimed, err := store.ClaimNotification(id, time.Minute); err != nil || claimed {
		t.Fatalf("second ClaimNotification() claimed=%v err=%v, want unclaimed", claimed, err)
	}
	return claim
}

func claimNotification(t *testing.T, store *Store, id string) NotificationClaim {
	t.Helper()
	claim, claimed, err := store.ClaimNotification(id, time.Minute)
	if err != nil || !claimed || claim.Grant.NotificationClaimedAt.IsZero() || claim.DecisionToken == "" {
		t.Fatalf("ClaimNotification() = %+v claimed=%v err=%v", claim, claimed, err)
	}
	return claim
}

func setClaimedNotification(t *testing.T, store *Store, id string, claimTime time.Time, ref notify.MessageRef) {
	t.Helper()
	assertInvalidNotificationRejected(t, store, id, claimTime)
	if _, recorded, err := store.SetNotificationIfClaimed(id, claimTime.Add(time.Second), ref); err != nil || recorded {
		t.Fatalf("SetNotificationIfClaimed(stale) recorded=%v err=%v", recorded, err)
	}
	stored, recorded, err := store.SetNotificationIfClaimed(id, claimTime, ref)
	if err != nil || !recorded || stored.Notification == nil || *stored.Notification != ref ||
		!stored.NotificationClaimedAt.IsZero() || !stored.NotificationClaimUntil.IsZero() {
		t.Fatalf("SetNotificationIfClaimed() = %+v recorded=%v err=%v", stored, recorded, err)
	}
}

func assertInvalidNotificationRejected(t *testing.T, store *Store, id string, claimTime time.Time) {
	t.Helper()
	if _, recorded, err := store.SetNotificationIfClaimed(id, claimTime, notify.MessageRef{Kind: "telegram"}); err == nil || recorded {
		t.Fatalf("SetNotificationIfClaimed(invalid ref) recorded=%v err=%v", recorded, err)
	}
}

func assertNotifiedRetryHasNoToken(t *testing.T, store *Store, requestID string) {
	t.Helper()
	retry, created, err := store.Request(testGrantRequest(requestID, 1))
	if err != nil || created || retry.DecisionToken != "" {
		t.Fatalf("Request(notified retry) = %+v created=%v err=%v, want no replacement token", retry, created, err)
	}
}

func TestStaleReservationIsRetainedAcrossExpiry(t *testing.T) {
	now := time.Date(2026, 7, 10, 3, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:                func() time.Time { return now },
		ReservationTimeout: time.Minute,
	})
	result := requestTestGrant(t, store, "stale-reservation", 2)
	setTestNotification(t, store, result.Grant.ID)
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	reserved, err := store.ReserveUse(result.Grant.ID)
	if err != nil || reserved.ReservedAt.IsZero() {
		t.Fatalf("ReserveUse() = %+v err=%v", reserved, err)
	}
	now = now.Add(2 * time.Minute)
	update := assertSingleDueUpdate(t, store, StatusUpdateRetainedReservation, StatusActive, "reserved:active:1:0:1")
	if !update.Grant.ReservationRetained {
		t.Fatalf("retained update = %+v, want retained reservation", update)
	}
	if err := store.MarkNotificationStatus(result.Grant.ID, update.NotificationStatusKey()); err != nil {
		t.Fatal(err)
	}

	now = result.Grant.CreatedAt.Add(10 * time.Minute)
	assertSingleDueUpdate(t, store, StatusUpdateRetainedReservation, StatusExpired, "reserved:expired:1:0:1")
	committed, err := store.CommitUse(result.Grant.ID)
	if err != nil || committed.UsedCount != 1 || committed.ReservedCount != 0 || committed.ReservationRetained {
		t.Fatalf("CommitUse(expired reservation) = %+v err=%v", committed, err)
	}
	assertSingleDueUpdate(t, store, StatusUpdateUsedExpired, StatusConsumed, NotificationStatusUsedExpired+":1")
}

func TestOverlappingReservationsAdvanceRecoveryClock(t *testing.T) {
	cases := []struct {
		name   string
		settle func(*Store, string) (Grant, error)
	}{
		{name: "commit", settle: func(store *Store, id string) (Grant, error) { return store.CommitUse(id) }},
		{name: "release", settle: func(store *Store, id string) (Grant, error) { return store.ReleaseUse(id) }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assertOverlappingReservationClock(t, test.name, test.settle)
		})
	}
}

func assertOverlappingReservationClock(t *testing.T, name string, settle func(*Store, string) (Grant, error)) { //nolint:cyclop
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
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(9 * time.Minute)
	second, err := store.ReserveUse(result.Grant.ID)
	if err != nil || !second.ReservedAt.Equal(now) || second.ReservationRevision != 2 {
		t.Fatalf("second ReserveUse() = %+v err=%v", second, err)
	}
	now = now.Add(2 * time.Minute)
	settled, err := settle(store, result.Grant.ID)
	if err != nil || settled.ReservedCount != 1 || !settled.ReservedAt.Equal(now) {
		t.Fatalf("%s overlapping reservation = %+v err=%v", name, settled, err)
	}
	now = now.Add(9 * time.Minute)
	if _, err := store.StatusUpdatesDue(); err != nil {
		t.Fatal(err)
	}
	fresh, err := store.Get(result.Grant.ID)
	if err != nil || fresh.ReservationRetained {
		t.Fatalf("fresh overlapping reservation = %+v err=%v", fresh, err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := store.StatusUpdatesDue(); err != nil {
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
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	retained, err := store.RetainUse(result.Grant.ID)
	if err != nil || !retained.ReservationRetained {
		t.Fatalf("RetainUse() = %+v err=%v", retained, err)
	}
	released, err := store.ReleaseUse(result.Grant.ID)
	if err != nil || released.ReservedCount != 0 || released.ReservationRetained || !released.ReservedAt.IsZero() {
		t.Fatalf("ReleaseUse() = %+v err=%v", released, err)
	}
	if _, err := store.RetainUse(result.Grant.ID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("RetainUse(without reservation) error=%v, want ErrNotActive", err)
	}
}

func TestRetainedReservationClosesGrantOverlay(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	result := requestTestGrant(t, store, "retained-overlay", 2)
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RetainUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if active, err := store.ActivePolicyGrants(); err != nil || len(active) != 0 {
		t.Fatalf("ActivePolicyGrants(retained) = %+v err=%v, want none", active, err)
	}
	if _, err := store.ReleaseUse(result.Grant.ID); err != nil {
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
	if _, err := store.Revoke(committed.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	settled, err := store.CommitUse(committed.ID)
	if err != nil || settled.Status != StatusRevoked || settled.UsedCount != 1 || settled.ReservedCount != 0 {
		t.Fatalf("CommitUse(revoked) = %+v err=%v", settled, err)
	}

	retained := approvedReservedGrant(t, store, "revoked-retain")
	setTestNotification(t, store, retained.ID)
	if _, err := store.Revoke(retained.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	update := assertSingleDueUpdate(t, store, StatusUpdateRetainedReservation, StatusRevoked, "reserved:revoked:1:0:1")
	if !update.Grant.ReservationRetained {
		t.Fatalf("revoked stale reservation = %+v, want retained", update.Grant)
	}
	if _, err := store.ReleaseUse(retained.ID); err != nil {
		t.Fatal(err)
	}
}

func TestCommittedUseRemainsDueAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	store := New(path, Options{})
	result := requestTestGrant(t, store, "used-recovery", 2)
	setTestNotification(t, store, result.Grant.ID)
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkNotificationStatus(result.Grant.ID, string(StatusActive)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	restarted := New(path, Options{})
	assertSingleDueUpdate(t, restarted, StatusUpdateUsed, StatusActive, NotificationStatusUsed+":active:1")
}

func TestSuccessiveUsesHaveDistinctDeliveryKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	store := New(path, Options{})
	result := requestTestGrant(t, store, "successive-uses", 3)
	setTestNotification(t, store, result.Grant.ID)
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkNotificationStatus(result.Grant.ID, string(StatusActive)); err != nil {
		t.Fatal(err)
	}
	commitTestUse(t, store, result.Grant.ID)
	first := assertSingleDueUpdate(t, store, StatusUpdateUsed, StatusActive, NotificationStatusUsed+":active:1")
	if err := store.MarkNotificationStatus(result.Grant.ID, first.NotificationStatusKey()); err != nil {
		t.Fatal(err)
	}
	commitTestUse(t, store, result.Grant.ID)
	restarted := New(path, Options{})
	assertSingleDueUpdate(t, restarted, StatusUpdateUsed, StatusActive, NotificationStatusUsed+":active:2")
}

func TestRepeatedRetainedReservationsHaveDistinctDeliveryKeys(t *testing.T) {
	now := time.Date(2026, 7, 10, 5, 0, 0, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:                func() time.Time { return now },
		ReservationTimeout: time.Minute,
	})
	result := requestTestGrant(t, store, "repeated-reservations", 2)
	setTestNotification(t, store, result.Grant.ID)
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkNotificationStatus(result.Grant.ID, string(StatusActive)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	first := assertSingleDueUpdate(t, store, StatusUpdateRetainedReservation, StatusActive, "reserved:active:1:0:1")
	if err := store.MarkNotificationStatus(result.Grant.ID, first.NotificationStatusKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReleaseUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(result.Grant.ID); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	assertSingleDueUpdate(t, store, StatusUpdateRetainedReservation, StatusActive, "reserved:active:2:0:1")
}

func TestRevokedLateCommitProducesUseUpdate(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	grant := approvedReservedGrant(t, store, "revoked-late-use")
	setTestNotification(t, store, grant.ID)
	if _, err := store.Revoke(grant.ID, "operator"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkNotificationStatus(grant.ID, string(StatusRevoked)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(grant.ID); err != nil {
		t.Fatal(err)
	}
	assertSingleDueUpdate(t, store, StatusUpdateUsed, StatusRevoked, NotificationStatusUsed+":revoked:1")
}

func requestTestGrant(t *testing.T, store *Store, requestID string, maxUses int) RequestResult {
	t.Helper()
	result, created, err := store.Request(testGrantRequest(requestID, maxUses))
	if err != nil || !created {
		t.Fatalf("Request() = %+v created=%v err=%v", result, created, err)
	}
	return result
}

func testGrantRequest(requestID string, maxUses int) Request {
	return Request{
		Client:          "bob",
		ClientRequestID: requestID,
		Operation:       "git.push.fast_forward",
		Target:          repoTarget("demo"),
		Attrs:           map[string][]string{"ref": {"refs/heads/main"}},
		Reason:          "test durable lifecycle",
		MaxUses:         maxUses,
	}
}

func setTestNotification(t *testing.T, store *Store, id string) {
	t.Helper()
	if _, err := store.SetNotification(id, notify.MessageRef{Kind: "telegram", ChatID: 42, MessageID: 7}); err != nil {
		t.Fatal(err)
	}
}

func approvedReservedGrant(t *testing.T, store *Store, requestID string) Grant {
	t.Helper()
	result := requestTestGrant(t, store, requestID, 1)
	approved, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator")
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := store.ReserveUse(approved.ID)
	if err != nil {
		t.Fatal(err)
	}
	return reserved
}

func commitTestUse(t *testing.T, store *Store, id string) {
	t.Helper()
	if _, err := store.ReserveUse(id); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(id); err != nil {
		t.Fatal(err)
	}
}

func assertSingleDueUpdate(t *testing.T, store *Store, kind StatusUpdateKind, status Status, key string) StatusUpdate {
	t.Helper()
	updates, err := store.StatusUpdatesDue()
	if err != nil || len(updates) != 1 {
		t.Fatalf("StatusUpdatesDue() = %+v err=%v, want one update", updates, err)
	}
	update := updates[0]
	if update.Kind != kind || update.Status != status || update.NotificationStatusKey() != key {
		t.Fatalf("StatusUpdatesDue()[0] = %+v, want kind=%s status=%s key=%s", update, kind, status, key)
	}
	return update
}

func assertNoDueUpdates(t *testing.T, store *Store) {
	t.Helper()
	updates, err := store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
}
