package grants

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/usebudget"
)

func TestApplyOperatorDecisionIsAtomicAndReplaySafe(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "grants.json")
	store := New(path, Options{})
	created, _, err := store.Request(Request{
		Client: "bob", ClientRequestID: "request-1", Operation: "write",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "update", Duration: 10 * time.Minute, MaxUses: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	validatorCalls := 0
	command := OperatorDecision{
		ID: created.Grant.ID, Action: ActionApprove, Approver: "operator:onur",
		OnBehalfOf: "Onur", ExpectedRevision: created.Grant.Revision,
		IdempotencyKey: "decision-1",
		Constraints:    ApprovalConstraints{Duration: 5 * time.Minute, MaxUses: 1},
	}
	result, err := store.ApplyOperatorDecision(t.Context(), command, func(_ context.Context, grant Grant, constraints ApprovalConstraints) error {
		validatorCalls++
		if grant.ID != created.Grant.ID || constraints.MaxUses != 1 {
			t.Fatalf("validator input = %+v %+v", grant, constraints)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Replay || result.Grant.Status != StatusActive || result.Grant.MaxUses != 1 ||
		result.Grant.RequestedMaxUses != 3 || result.Grant.RequestedDuration != 10*time.Minute ||
		result.Grant.DecidedOnBehalfOf != "Onur" {
		t.Fatalf("result = %+v", result)
	}

	restarted := New(path, Options{})
	replay, err := restarted.ApplyOperatorDecision(t.Context(), command, func(context.Context, Grant, ApprovalConstraints) error {
		t.Fatal("validator called during replay")
		return nil
	})
	if err != nil || !replay.Replay || replay.Grant.Revision != result.Grant.Revision {
		t.Fatalf("replay = %+v, err = %v", replay, err)
	}
	if validatorCalls != 1 {
		t.Fatalf("validator calls = %d", validatorCalls)
	}

	changed := command
	changed.OnBehalfOf = "different"
	if _, err := restarted.ApplyOperatorDecision(t.Context(), changed, nil); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay error = %v", err)
	}
}

func TestApplyOperatorDecisionFailsClosed(t *testing.T) {
	t.Parallel()
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	created, _, err := store.Request(Request{
		Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"},
		Reason: "update", Duration: time.Minute, MaxUses: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	base := OperatorDecision{
		ID: created.Grant.ID, Action: ActionApprove, Approver: "operator:onur",
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "decision-1",
	}
	widened := base
	widened.Constraints.Duration = 2 * time.Minute
	if _, err := store.ApplyOperatorDecision(t.Context(), widened, nil); !errors.Is(err, ErrConstraintExceeded) {
		t.Fatalf("widened error = %v", err)
	}
	rejected := errors.New("provider plan invalid")
	if _, err := store.ApplyOperatorDecision(t.Context(), base, func(context.Context, Grant, ApprovalConstraints) error { return rejected }); !errors.Is(err, rejected) {
		t.Fatalf("validator error = %v", err)
	}
	current, err := store.Get(created.Grant.ID)
	if err != nil || current.Status != StatusPending || current.Revision != created.Grant.Revision {
		t.Fatalf("current = %+v, err = %v", current, err)
	}
	stale := base
	stale.ExpectedRevision++
	if _, err := store.ApplyOperatorDecision(t.Context(), stale, nil); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("stale error = %v", err)
	}
}

func TestApprovalMayNarrowUnlimitedUseBudget(t *testing.T) {
	t.Parallel()
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	created, _, err := store.Request(Request{
		Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"},
		Reason: "maintenance", Duration: time.Minute,
		MaxUses: usebudget.Unlimited, MaxUsesSpecified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := store.ApplyOperatorDecision(t.Context(), OperatorDecision{
		ID: created.Grant.ID, Action: ActionApprove, Approver: "operator:onur",
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "finite",
		Constraints: ApprovalConstraints{MaxUses: 3, MaxUsesSpecified: true},
	}, nil)
	if err != nil || result.Grant.MaxUses != 3 || !result.Grant.RequestedMaxUses.IsUnlimited() {
		t.Fatalf("ApplyOperatorDecision() = %+v, %v", result, err)
	}
}

func TestApprovalCannotWidenFiniteUseBudgetToUnlimited(t *testing.T) {
	t.Parallel()
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	created, _, err := store.Request(Request{
		Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"},
		Reason: "maintenance", Duration: time.Minute, MaxUses: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ApplyOperatorDecision(t.Context(), OperatorDecision{
		ID: created.Grant.ID, Action: ActionApprove, Approver: "operator:onur",
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "unlimited",
		Constraints: ApprovalConstraints{MaxUses: usebudget.Unlimited, MaxUsesSpecified: true},
	}, nil)
	if !errors.Is(err, ErrConstraintExceeded) {
		t.Fatalf("ApplyOperatorDecision() error = %v", err)
	}
}
