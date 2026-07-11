package decision

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorv1"
	"github.com/osolmaz/brokerkit/policy"
)

func TestServiceUsesValidatorForRevisionAndTokenApproval(t *testing.T) {
	t.Parallel()
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	calls := 0
	service, err := New(store, ActivationValidatorFunc(func(_ context.Context, _ grants.Grant, constraints grants.ApprovalConstraints) error {
		calls++
		if calls == 1 && constraints.MaxUses != 1 {
			t.Fatalf("constraints = %+v", constraints)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	first := create(t, store, "first")
	result, err := service.Decide(t.Context(), first.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: first.Grant.Revision, IdempotencyKey: "decision-1", Constraints: &operatorv1.Constraints{DurationSeconds: 60, MaxUses: 1},
	})
	if err != nil || result.Grant.Status != grants.StatusActive {
		t.Fatalf("Decide() = %+v, %v", result, err)
	}
	second := create(t, store, "second")
	approved, err := service.ApproveToken(t.Context(), second.Grant.ID, second.DecisionToken, "telegram:onur", notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2})
	if err != nil || approved.Status != grants.StatusActive || calls != 2 {
		t.Fatalf("ApproveToken() = %+v, %v calls=%d", approved, err, calls)
	}
}

func TestServiceRejectsInvalidInputAndValidatorFailure(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, nil); err == nil {
		t.Fatal("New(nil) succeeded")
	}
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	rejected := errors.New("plan invalid")
	service, _ := New(store, ActivationValidatorFunc(func(context.Context, grants.Grant, grants.ApprovalConstraints) error { return rejected }))
	created := create(t, store, "request")
	if _, err := service.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "decision", Constraints: &operatorv1.Constraints{DurationSeconds: -1},
	}); !errors.Is(err, grants.ErrInvalidCommand) {
		t.Fatalf("invalid constraint error = %v", err)
	}
	ref := notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2}
	if _, err := service.ApproveToken(t.Context(), created.Grant.ID, created.DecisionToken, "operator:onur", ref); !errors.Is(err, rejected) {
		t.Fatalf("validator error = %v", err)
	}
	denied, err := service.DenyToken(t.Context(), created.Grant.ID, created.DecisionToken, "operator:onur", ref)
	if err != nil || denied.Status != grants.StatusDenied {
		t.Fatalf("DenyToken() = %+v, %v", denied, err)
	}
}

func TestTokenApprovalValidationAndCommitAreAtomic(t *testing.T) {
	t.Parallel()
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	created := create(t, store, "atomic-token")
	validationStarted := make(chan struct{})
	releaseValidation := make(chan struct{})
	service, err := New(store, ActivationValidatorFunc(func(context.Context, grants.Grant, grants.ApprovalConstraints) error {
		close(validationStarted)
		<-releaseValidation
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	ref := notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2}
	approveDone := make(chan error, 1)
	go func() {
		_, approveErr := service.ApproveToken(t.Context(), created.Grant.ID, created.DecisionToken, "telegram:onur", ref)
		approveDone <- approveErr
	}()
	<-validationStarted
	denyDone := make(chan error, 1)
	go func() {
		_, denyErr := service.DenyToken(t.Context(), created.Grant.ID, created.DecisionToken, "telegram:onur", ref)
		denyDone <- denyErr
	}()
	select {
	case err := <-denyDone:
		t.Fatalf("concurrent denial completed during activation validation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseValidation)
	if err := <-approveDone; err != nil {
		t.Fatalf("ApproveToken() error = %v", err)
	}
	if err := <-denyDone; !errors.Is(err, grants.ErrNotPending) {
		t.Fatalf("DenyToken() error = %v, want ErrNotPending", err)
	}
}

func create(t *testing.T, store *grants.Store, id string) grants.RequestResult {
	t.Helper()
	result, _, err := store.Request(grants.Request{Client: "bob", ClientRequestID: id, Operation: "write", Target: policy.Target{Kind: "repo"}, Reason: "test", Duration: time.Minute, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
