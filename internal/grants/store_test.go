package grants

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGrantLifecycleApproveUseAndReplay(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})

	grant, created, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_history_rewrite",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "recover main",
		RequestedDuration: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if !created {
		t.Fatalf("Request() created = false, want true")
	}
	if grant.Status != StatusPending || grant.DecisionToken == "" || grant.RequestedMinutes != 5 || grant.MaxUses != 1 {
		t.Fatalf("grant = %+v", grant)
	}
	if _, _, err := store.MatchActive(grant.Client, grant.Operation, grant.Target, grant.Ref); err != nil {
		t.Fatalf("MatchActive() error = %v", err)
	}

	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if approved.Status != StatusActive || approved.DecidedBy != "telegram:1" {
		t.Fatalf("approved = %+v", approved)
	}
	if _, err := store.Deny(grant.ID, grant.DecisionToken, "telegram:1"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("replayed Deny() error = %v, want ErrNotPending", err)
	}

	matched, ok, err := store.MatchActive(grant.Client, grant.Operation, grant.Target, grant.Ref)
	if err != nil || !ok {
		t.Fatalf("MatchActive() = %+v %v %v, want active", matched, ok, err)
	}
	if matched, ok, err := store.MatchActive("other-client", grant.Operation, grant.Target, grant.Ref); err != nil || ok {
		t.Fatalf("cross-client MatchActive() = %+v %v %v, want no match", matched, ok, err)
	}
	now = now.Add(time.Minute)
	used, err := store.RecordUse(matched.ID)
	if err != nil {
		t.Fatalf("RecordUse() error = %v", err)
	}
	if used.UsedAt.IsZero() {
		t.Fatalf("used grant missing UsedAt: %+v", used)
	}
	if used.Status != StatusConsumed || used.UsedCount != 1 {
		t.Fatalf("used grant status/count = %+v", used)
	}

	if _, ok, err := store.MatchActive(grant.Client, grant.Operation, grant.Target, grant.Ref); err != nil || ok {
		t.Fatalf("consumed MatchActive() ok=%v err=%v, want false nil", ok, err)
	}
	if _, err := store.RecordUse(grant.ID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("consumed RecordUse() error = %v, want ErrNotActive", err)
	}
}

func TestGrantDenyTokenAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:            func() time.Time { return now },
		PendingTimeout: time.Minute,
	})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/tags/v1",
		Reason:    "retag",
	})
	if err != nil {
		t.Fatal(err)
	}
	if grant.RequestedMinutes != 5 {
		t.Fatalf("default grant minutes = %d, want 5", grant.RequestedMinutes)
	}
	if _, err := store.Approve(grant.ID, "wrong", "telegram:1"); !errors.Is(err, ErrInvalidDecisionToken) {
		t.Fatalf("Approve(wrong token) error = %v, want ErrInvalidDecisionToken", err)
	}
	denied, err := store.Deny(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	if denied.Status != StatusDenied || denied.DecidedBy != "telegram:1" {
		t.Fatalf("denied = %+v", denied)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("Approve(denied) error = %v, want ErrNotPending", err)
	}

	expiring, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "expire",
	})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := store.Deny(expiring.ID, expiring.DecisionToken, "telegram:1"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("Deny(expired) error = %v, want ErrNotPending", err)
	}
}

func TestGrantCancelAndMissing(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	if err := store.Cancel("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Cancel(missing) error = %v, want ErrNotFound", err)
	}
	grant, _, err := store.Request(Request{
		Client:          "agent",
		ClientRequestID: "notify-failure",
		Operation:       "git_history_rewrite",
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Reason:          "notify failure",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Cancel(grant.ID); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("Approve(canceled) error = %v, want ErrNotPending", err)
	}

	retry, created, err := store.Request(Request{
		Client:          "agent",
		ClientRequestID: "notify-failure",
		Operation:       "git_history_rewrite",
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Reason:          "notify failure",
	})
	if err != nil {
		t.Fatalf("retry Request() error = %v", err)
	}
	if !created || retry.ID == grant.ID || retry.Status != StatusPending {
		t.Fatalf("retry after canceled grant = %+v created=%v, want new pending grant", retry, created)
	}
}

func TestGrantNotifierClaimSerializesAndExpires(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:          "agent",
		ClientRequestID: "notify-once",
		Operation:       "git_history_rewrite",
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Reason:          "notify once",
	})
	if err != nil {
		t.Fatal(err)
	}

	claimedGrant, claimed, err := store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first ClaimNotifier() = %+v claimed=%v err=%v, want claimed", claimedGrant, claimed, err)
	}
	if !claimedGrant.NotifierClaimedAt.Equal(now) {
		t.Fatalf("claim timestamp = %s, want %s", claimedGrant.NotifierClaimedAt, now)
	}
	_, claimed, err = store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || claimed {
		t.Fatalf("second ClaimNotifier() claimed=%v err=%v, want unclaimed nil", claimed, err)
	}

	now = now.Add(3 * time.Minute)
	reclaimed, claimed, err := store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("stale ClaimNotifier() = %+v claimed=%v err=%v, want claimed", reclaimed, claimed, err)
	}
	if !reclaimed.NotifierClaimedAt.Equal(now) {
		t.Fatalf("reclaim timestamp = %s, want %s", reclaimed.NotifierClaimedAt, now)
	}

	withNotifier, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"})
	if err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	if !withNotifier.NotifierClaimedAt.IsZero() {
		t.Fatalf("SetNotifier() kept claim timestamp: %+v", withNotifier)
	}
	_, claimed, err = store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || claimed {
		t.Fatalf("ClaimNotifier() after SetNotifier claimed=%v err=%v, want unclaimed nil", claimed, err)
	}
}

func TestSetNotifierIfClaimedRejectsStaleClaim(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "notify once",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, claimed, err := store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first ClaimNotifier() claimed=%v err=%v, want claimed", claimed, err)
	}
	now = now.Add(3 * time.Minute)
	second, claimed, err := store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("second ClaimNotifier() claimed=%v err=%v, want claimed", claimed, err)
	}

	stale, recorded, err := store.SetNotifierIfClaimed(grant.ID, first.NotifierClaimedAt, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 1, Text: "stale"})
	if err != nil || recorded {
		t.Fatalf("stale SetNotifierIfClaimed() recorded=%v err=%v, want false nil", recorded, err)
	}
	if stale.Notifier != nil || !stale.NotifierClaimedAt.Equal(second.NotifierClaimedAt) {
		t.Fatalf("stale SetNotifierIfClaimed() grant = %+v, want current claim without notifier", stale)
	}
	current, recorded, err := store.SetNotifierIfClaimed(grant.ID, second.NotifierClaimedAt, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "current"})
	if err != nil || !recorded {
		t.Fatalf("current SetNotifierIfClaimed() recorded=%v err=%v, want true nil", recorded, err)
	}
	if current.Notifier == nil || current.Notifier.MessageID != 2 || !current.NotifierClaimedAt.IsZero() {
		t.Fatalf("current SetNotifierIfClaimed() grant = %+v, want recorded current notifier", current)
	}
}

func TestCancelIfNotifierClaimedRejectsStaleClaim(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "notify once",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, claimed, err := store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first ClaimNotifier() claimed=%v err=%v, want claimed", claimed, err)
	}
	now = now.Add(3 * time.Minute)
	second, claimed, err := store.ClaimNotifier(grant.ID, 2*time.Minute)
	if err != nil || !claimed {
		t.Fatalf("second ClaimNotifier() claimed=%v err=%v, want claimed", claimed, err)
	}

	stale, canceled, err := store.CancelIfNotifierClaimed(grant.ID, first.NotifierClaimedAt)
	if err != nil || canceled {
		t.Fatalf("stale CancelIfNotifierClaimed() canceled=%v err=%v, want false nil", canceled, err)
	}
	if stale.Status != StatusPending || !stale.NotifierClaimedAt.Equal(second.NotifierClaimedAt) {
		t.Fatalf("stale CancelIfNotifierClaimed() grant = %+v, want current pending claim", stale)
	}
	current, canceled, err := store.CancelIfNotifierClaimed(grant.ID, second.NotifierClaimedAt)
	if err != nil || !canceled {
		t.Fatalf("current CancelIfNotifierClaimed() canceled=%v err=%v, want true nil", canceled, err)
	}
	if current.Status != StatusCanceled || !current.NotifierClaimedAt.IsZero() {
		t.Fatalf("current CancelIfNotifierClaimed() grant = %+v, want canceled without claim", current)
	}
}

func TestGrantUseReservationCommitAndRelease(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "force push",
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	reserved, err := store.ReserveUse(approved.ID)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	if reserved.ReservedCount != 1 || reserved.UsedCount != 0 || reserved.Status != StatusActive || !reserved.ReservedAt.Equal(now) {
		t.Fatalf("reserved grant = %+v, want one reservation on active grant", reserved)
	}
	if _, ok, err := store.MatchActive(grant.Client, grant.Operation, grant.Target, grant.Ref); err != nil || ok {
		t.Fatalf("reserved MatchActive() ok=%v err=%v, want false nil", ok, err)
	}
	released, err := store.ReleaseUse(approved.ID)
	if err != nil {
		t.Fatalf("ReleaseUse() error = %v", err)
	}
	if released.ReservedCount != 0 || released.Status != StatusActive || !released.ReservedAt.IsZero() {
		t.Fatalf("released grant = %+v, want active without reservation", released)
	}
	if _, ok, err := store.MatchActive(grant.Client, grant.Operation, grant.Target, grant.Ref); err != nil || !ok {
		t.Fatalf("released MatchActive() ok=%v err=%v, want true nil", ok, err)
	}

	if _, err := store.ReserveUse(approved.ID); err != nil {
		t.Fatalf("second ReserveUse() error = %v", err)
	}
	now = now.Add(time.Minute)
	committed, err := store.CommitUse(approved.ID)
	if err != nil {
		t.Fatalf("CommitUse() error = %v", err)
	}
	if committed.ReservedCount != 0 || committed.UsedCount != 1 || committed.Status != StatusConsumed || !committed.UsedAt.Equal(now) || !committed.ReservedAt.IsZero() {
		t.Fatalf("committed grant = %+v, want consumed use at %s", committed, now)
	}
	if _, err := store.CommitUse(approved.ID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("CommitUse() without reservation error = %v, want ErrNotActive", err)
	}
}

func TestCommitReservedUseAfterAccessWindowExpires(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_history_rewrite",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "slow accepted push",
		RequestedDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if _, err := store.ReserveUse(approved.ID); err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}

	now = now.Add(2 * time.Minute)
	committed, err := store.CommitUse(approved.ID)
	if err != nil {
		t.Fatalf("CommitUse() after expiry error = %v", err)
	}
	if committed.Status != StatusConsumed || committed.ReservedCount != 0 || committed.UsedCount != 1 {
		t.Fatalf("committed expired reservation = %+v, want consumed use", committed)
	}
}

func TestExpiredReservedUseKeepsUsedStatusUpdate(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_history_rewrite",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "slow accepted push",
		RequestedDuration: time.Minute,
		MaxUses:           3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(StatusActive)); err != nil {
		t.Fatalf("MarkNotifierStatus(active) error = %v", err)
	}
	if _, err := store.ReserveUse(approved.ID); err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	now = now.Add(2 * time.Minute)
	committed, err := store.CommitUse(approved.ID)
	if err != nil {
		t.Fatalf("CommitUse() error = %v", err)
	}
	if committed.Status != StatusExpired || committed.UsedCount != 1 || committed.ReservedCount != 0 {
		t.Fatalf("committed grant = %+v, want expired grant with one used reservation", committed)
	}

	updates, err := store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Status != StatusConsumed || updates[0].NotifierStatusKey() != string(NotifierStatusUsedExpired) {
		t.Fatalf("updates = %+v, want expired used status update", updates)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(NotifierStatusUsedExpired)); err != nil {
		t.Fatalf("MarkNotifierStatus(used:expired) error = %v", err)
	}
	updates, err = store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("second StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
}

func TestPartialUsedGrantExpirationUpdatesClosedStatus(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_history_rewrite",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "multi-use push",
		RequestedDuration: time.Minute,
		MaxUses:           3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if _, err := store.RecordUse(grant.ID); err != nil {
		t.Fatalf("RecordUse() error = %v", err)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(NotifierStatusUsed)); err != nil {
		t.Fatalf("MarkNotifierStatus(used) error = %v", err)
	}

	now = now.Add(2 * time.Minute)
	updates, err := store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Status != StatusConsumed || updates[0].NotifierStatusKey() != string(NotifierStatusUsedExpired) {
		t.Fatalf("updates = %+v, want expired used status update", updates)
	}
}

func TestGrantRequestValidation(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	if _, _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_history_rewrite",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "too long",
		RequestedDuration: 2 * time.Hour,
	}); err == nil {
		t.Fatalf("Request() accepted overlong duration")
	}
	if _, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
	}); err == nil {
		t.Fatalf("Request() accepted empty reason")
	}
	if _, _, err := store.Request(Request{
		Client:  "agent",
		Reason:  "bad uses",
		MaxUses: -1,
	}); err == nil {
		t.Fatalf("Request() accepted negative max uses")
	}
}

func TestGrantMultiUseAndNotifierMetadata(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, created, err := store.Request(Request{
		Client:          "agent",
		ClientRequestID: "req-1",
		Operation:       "git_history_rewrite",
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Reason:          "recover twice",
		MaxUses:         2,
	})
	if err != nil {
		t.Fatalf("Request() error = %v", err)
	}
	if !created || grant.MaxUses != 2 {
		t.Fatalf("grant created=%v grant=%+v", created, grant)
	}
	again, created, err := store.Request(Request{
		Client:          "agent",
		ClientRequestID: "req-1",
		Operation:       "git_history_rewrite",
		Target:          "dataset/acme/repo",
		Ref:             "refs/heads/main",
		Reason:          "recover twice",
		MaxUses:         2,
	})
	if err != nil || created || again.ID != grant.ID {
		t.Fatalf("idempotent Request() = %+v created=%v err=%v, want existing", again, created, err)
	}
	withNotifier, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"})
	if err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	if withNotifier.Notifier == nil || withNotifier.Notifier.MessageID != 2 {
		t.Fatalf("notifier metadata = %+v", withNotifier.Notifier)
	}
	if err := store.MarkNotifierStatus(grant.ID, "sent"); err != nil {
		t.Fatalf("MarkNotifierStatus() error = %v", err)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	used, err := store.RecordUse(grant.ID)
	if err != nil {
		t.Fatalf("first RecordUse() error = %v", err)
	}
	if used.Status != StatusActive || used.UsedCount != 1 {
		t.Fatalf("first use = %+v", used)
	}
	used, err = store.RecordUse(grant.ID)
	if err != nil {
		t.Fatalf("second RecordUse() error = %v", err)
	}
	if used.Status != StatusConsumed || used.UsedCount != 2 {
		t.Fatalf("second use = %+v", used)
	}
}

func TestLegacyUsedGrantLoadsConsumed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "grants.json")
	raw := `{"grants":[{
		"id":"grant-id",
		"decision_token":"decision-token",
		"client":"agent",
		"operation":"git_history_rewrite",
		"target":"dataset/acme/repo",
		"ref":"refs/heads/main",
		"reason":"legacy use",
		"requested_minutes":5,
		"status":"active",
		"created_at":"2026-07-06T01:02:03Z",
		"pending_expires_at":"2026-07-06T01:12:03Z",
		"expires_at":"2099-01-01T00:00:00Z",
		"used_at":"2026-07-06T01:03:03Z"
	}]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	store := New(path, Options{})

	if grant, ok, err := store.MatchActive("agent", "git_history_rewrite", "dataset/acme/repo", "refs/heads/main"); err != nil || ok {
		t.Fatalf("legacy used MatchActive() = %+v ok=%v err=%v, want no active grant", grant, ok, err)
	}
}

func TestConsumedGrantStatusUpdateDue(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "single use",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	if _, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if _, err := store.RecordUse(grant.ID); err != nil {
		t.Fatalf("RecordUse() error = %v", err)
	}
	updates, err := store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Grant.ID != grant.ID || updates[0].Status != StatusConsumed {
		t.Fatalf("updates = %+v, want consumed grant", updates)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(StatusConsumed)); err != nil {
		t.Fatalf("MarkNotifierStatus() error = %v", err)
	}
	updates, err = store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("second StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
}

func TestRetainedReservationStatusUpdateDue(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_history_rewrite",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "ambiguous push",
		RequestedDuration: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(StatusActive)); err != nil {
		t.Fatalf("MarkNotifierStatus(active) error = %v", err)
	}
	if _, err := store.ReserveUse(approved.ID); err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	if _, err := store.RetainUse(approved.ID); err != nil {
		t.Fatalf("RetainUse() error = %v", err)
	}

	updates, err := store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Grant.ID != grant.ID || updates[0].Status != NotifierStatusReserved {
		t.Fatalf("updates = %+v, want retained reservation update", updates)
	}
	activeRetainedStatus := updates[0].NotifierStatusKey()
	if activeRetainedStatus != "reserved:active" {
		t.Fatalf("active retained status key = %q, want reserved:active", activeRetainedStatus)
	}
	if err := store.MarkNotifierStatus(grant.ID, activeRetainedStatus); err != nil {
		t.Fatalf("MarkNotifierStatus(reserved) error = %v", err)
	}
	updates, err = store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("second StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}

	now = now.Add(2 * time.Minute)
	updates, err = store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("expired reserved StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Grant.ID != grant.ID || updates[0].Status != NotifierStatusReserved || updates[0].NotifierStatusKey() != "reserved:expired" {
		t.Fatalf("expired reserved StatusUpdatesDue() = %+v, want expired retained reservation update", updates)
	}
	if err := store.MarkNotifierStatus(grant.ID, updates[0].NotifierStatusKey()); err != nil {
		t.Fatalf("MarkNotifierStatus(expired reserved) error = %v", err)
	}
	updates, err = store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("second expired reserved StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
	expired, err := store.Get(grant.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", grant.ID, err)
	}
	if expired.Status != StatusExpired || expired.ReservedCount != 1 || expired.NotifierStatus != "reserved:expired" {
		t.Fatalf("expired reserved grant = %+v, want expired held reservation with reserved notifier status", expired)
	}
}

func TestInFlightReservationStatusUpdateDue(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "slow push",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(StatusActive)); err != nil {
		t.Fatalf("MarkNotifierStatus(active) error = %v", err)
	}
	reserved, err := store.ReserveUse(approved.ID)
	if err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}
	if reserved.ReservationRetained {
		t.Fatalf("reserved grant = %+v, want in-flight reservation without retained marker", reserved)
	}

	updates, err := store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("in-flight StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
	released, err := store.ReleaseUse(approved.ID)
	if err != nil {
		t.Fatalf("ReleaseUse() error = %v", err)
	}
	if released.ReservedCount != 0 || released.ReservationRetained || released.NotifierStatus != string(StatusActive) {
		t.Fatalf("released grant = %+v, want active grant without retained reservation", released)
	}
}

func TestStaleReservationStatusUpdateDue(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:                func() time.Time { return now },
		ReservationTimeout: time.Minute,
	})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "crashed push",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	approved, err := store.Approve(grant.ID, grant.DecisionToken, "telegram:1")
	if err != nil {
		t.Fatalf("Approve() error = %v", err)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(StatusActive)); err != nil {
		t.Fatalf("MarkNotifierStatus(active) error = %v", err)
	}
	if _, err := store.ReserveUse(approved.ID); err != nil {
		t.Fatalf("ReserveUse() error = %v", err)
	}

	now = now.Add(time.Minute - time.Nanosecond)
	updates, err := store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("pre-timeout StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
	now = now.Add(time.Nanosecond)
	updates, err = store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("stale StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 1 || updates[0].Status != NotifierStatusReserved || updates[0].NotifierStatusKey() != "reserved:active" {
		t.Fatalf("stale StatusUpdatesDue() = %+v, want retained reservation update", updates)
	}
	current, err := store.Get(grant.ID)
	if err != nil {
		t.Fatalf("Get(%q) error = %v", grant.ID, err)
	}
	if !current.ReservationRetained || current.ReservedCount != 1 {
		t.Fatalf("stale reservation grant = %+v, want retained reservation", current)
	}
}

func TestDecisionStatusUpdatesDue(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	approved, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "approve",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(approved.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier(approved) error = %v", err)
	}
	if _, err := store.Approve(approved.ID, approved.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Approve() error = %v", err)
	}

	denied, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/dev",
		Reason:    "deny",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(denied.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 3, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier(denied) error = %v", err)
	}
	if _, err := store.Deny(denied.ID, denied.DecisionToken, "telegram:1"); err != nil {
		t.Fatalf("Deny() error = %v", err)
	}

	updates, err := store.StatusUpdatesDue()
	if err != nil {
		t.Fatalf("StatusUpdatesDue() error = %v", err)
	}
	if len(updates) != 2 || updates[0].Status != StatusActive || updates[1].Status != StatusDenied {
		t.Fatalf("updates = %+v, want active and denied", updates)
	}
	if err := store.MarkNotifierStatus(approved.ID, string(StatusActive)); err != nil {
		t.Fatalf("MarkNotifierStatus(active) error = %v", err)
	}
	if err := store.MarkNotifierStatus(denied.ID, string(StatusDenied)); err != nil {
		t.Fatalf("MarkNotifierStatus(denied) error = %v", err)
	}
	updates, err = store.StatusUpdatesDue()
	if err != nil || len(updates) != 0 {
		t.Fatalf("second StatusUpdatesDue() = %+v err=%v, want none", updates, err)
	}
}

func TestGrantExpireDueReturnsNotifierUpdates(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:            func() time.Time { return now },
		PendingTimeout: time.Minute,
	})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_history_rewrite",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "expire pending",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetNotifier(grant.ID, NotifierMessage{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "grant text"}); err != nil {
		t.Fatalf("SetNotifier() error = %v", err)
	}
	now = now.Add(time.Minute)
	expired, err := store.ExpireDue()
	if err != nil {
		t.Fatalf("ExpireDue() error = %v", err)
	}
	if len(expired) != 1 || expired[0].Grant.ID != grant.ID || expired[0].ExpiredFrom != StatusPending {
		t.Fatalf("expired = %+v", expired)
	}
	if err := store.MarkNotifierStatus(grant.ID, string(StatusExpired)); err != nil {
		t.Fatalf("MarkNotifierStatus() error = %v", err)
	}
	expired, err = store.ExpireDue()
	if err != nil || len(expired) != 0 {
		t.Fatalf("second ExpireDue() = %+v err=%v, want none", expired, err)
	}
}
