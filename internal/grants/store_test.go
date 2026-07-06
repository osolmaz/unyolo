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
		Operation:         "git_receive_pack",
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
		Operation: "git_receive_pack",
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
		Operation: "git_receive_pack",
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
		Operation:       "git_receive_pack",
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
		Operation:       "git_receive_pack",
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

func TestGrantRequestValidation(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	if _, _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_receive_pack",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "too long",
		RequestedDuration: 2 * time.Hour,
	}); err == nil {
		t.Fatalf("Request() accepted overlong duration")
	}
	if _, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_receive_pack",
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
		Operation:       "git_receive_pack",
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
		Operation:       "git_receive_pack",
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
		"operation":"git_receive_pack",
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

	if grant, ok, err := store.MatchActive("agent", "git_receive_pack", "dataset/acme/repo", "refs/heads/main"); err != nil || ok {
		t.Fatalf("legacy used MatchActive() = %+v ok=%v err=%v, want no active grant", grant, ok, err)
	}
}

func TestConsumedGrantStatusUpdateDue(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})
	grant, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_receive_pack",
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

func TestDecisionStatusUpdatesDue(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	approved, _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_receive_pack",
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
		Operation: "git_receive_pack",
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
		Operation: "git_receive_pack",
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
