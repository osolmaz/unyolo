package grants

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestGrantLifecycleApproveUseAndReplay(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{Now: func() time.Time { return now }})

	grant, err := store.Request(Request{
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
	if grant.Status != StatusPending || grant.DecisionToken == "" || grant.RequestedMinutes != 5 {
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

	now = now.Add(5 * time.Minute)
	if _, ok, err := store.MatchActive(grant.Client, grant.Operation, grant.Target, grant.Ref); err != nil || ok {
		t.Fatalf("expired MatchActive() ok=%v err=%v, want false nil", ok, err)
	}
	if _, err := store.RecordUse(grant.ID); !errors.Is(err, ErrNotActive) {
		t.Fatalf("expired RecordUse() error = %v, want ErrNotActive", err)
	}
}

func TestGrantDenyTokenAndExpiry(t *testing.T) {
	now := time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC)
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{
		Now:            func() time.Time { return now },
		PendingTimeout: time.Minute,
	})
	grant, err := store.Request(Request{
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

	expiring, err := store.Request(Request{
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
	grant, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_receive_pack",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
		Reason:    "notify failure",
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
}

func TestGrantRequestValidation(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	if _, err := store.Request(Request{
		Client:            "agent",
		Operation:         "git_receive_pack",
		Target:            "dataset/acme/repo",
		Ref:               "refs/heads/main",
		Reason:            "too long",
		RequestedDuration: 2 * time.Hour,
	}); err == nil {
		t.Fatalf("Request() accepted overlong duration")
	}
	if _, err := store.Request(Request{
		Client:    "agent",
		Operation: "git_receive_pack",
		Target:    "dataset/acme/repo",
		Ref:       "refs/heads/main",
	}); err == nil {
		t.Fatalf("Request() accepted empty reason")
	}
}
