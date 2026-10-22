package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

type decisionObserver struct{ values []string }

func (o *decisionObserver) OperatorDecision(action, result string) {
	o.values = append(o.values, action+":"+result)
}

func TestServiceUsesValidatorForEveryApproval(t *testing.T) {
	t.Parallel()
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	calls := 0
	service, err := New(Options{Store: store, Validator: ActivationValidatorFunc(func(_ context.Context, _ grants.Grant, constraints grants.ApprovalConstraints) error {
		calls++
		if calls == 1 && constraints.MaxUses != 1 {
			t.Fatalf("constraints = %+v", constraints)
		}
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	first := create(t, store, "first")
	result, err := service.Decide(t.Context(), first.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: first.Grant.Revision, IdempotencyKey: "decision-1", Constraints: &operatorv1.Constraints{DurationSeconds: 60, MaxUses: usebudget.Finite(1)},
	})
	if err != nil || result.Grant.Status != grants.StatusActive {
		t.Fatalf("Decide() = %+v, %v", result, err)
	}
	second := create(t, store, "second")
	approved, err := service.Decide(t.Context(), second.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: second.Grant.Revision, IdempotencyKey: "decision-2", OnBehalfOf: "telegram:42",
	})
	if err != nil || approved.Grant.Status != grants.StatusActive || calls != 2 {
		t.Fatalf("second Decide() = %+v, %v calls=%d", approved, err, calls)
	}
}

func TestServiceReportsBoundedDecisionOutcomes(t *testing.T) {
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	observer := &decisionObserver{}
	service, err := New(Options{Store: store, Observer: observer})
	if err != nil {
		t.Fatal(err)
	}
	request := create(t, store, "observed")
	command := operatorv1.Decision{ExpectedRevision: request.Grant.Revision, IdempotencyKey: "observed-decision"}
	if _, err := service.Decide(t.Context(), request.Grant.ID, operatorv1.ActionDeny, "operator", command); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decide(t.Context(), request.Grant.ID, operatorv1.ActionDeny, "operator", command); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Decide(t.Context(), "missing", operatorv1.ActionApprove, "operator", command); err == nil {
		t.Fatal("missing decision unexpectedly succeeded")
	}
	want := []string{"deny:committed", "deny:replayed", "approve:rejected"}
	if !slices.Equal(observer.values, want) {
		t.Fatalf("decision observations = %v, want %v", observer.values, want)
	}
}

func TestServiceAuditsRevisionDecisions(t *testing.T) {
	t.Parallel()
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	var output bytes.Buffer
	service, err := New(Options{Store: store, Broker: "test-broker", Audit: audit.New(&output)})
	if err != nil {
		t.Fatal(err)
	}
	first := create(t, store, "audit-revision")
	if _, err := service.Decide(t.Context(), first.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: first.Grant.Revision, IdempotencyKey: "audit-1", OnBehalfOf: "onur",
		Constraints: &operatorv1.Constraints{DurationSeconds: 60, MaxUses: usebudget.Finite(1)},
	}); err != nil {
		t.Fatal(err)
	}
	second := create(t, store, "audit-telegram")
	if _, err := service.Decide(t.Context(), second.Grant.ID, operatorv1.ActionApprove, "operator:telegram", operatorv1.Decision{
		ExpectedRevision: second.Grant.Revision, IdempotencyKey: "audit-2", OnBehalfOf: "telegram:42",
	}); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d\n%s", len(lines), output.String())
	}
	var events [2]audit.Event
	for index := range lines {
		if err := json.Unmarshal(lines[index], &events[index]); err != nil {
			t.Fatal(err)
		}
		if events[index].Extensions["previous_status"] != string(grants.StatusPending) ||
			events[index].Extensions["current_status"] != string(grants.StatusActive) ||
			events[index].Extensions["event_cursor"] == "" {
			t.Fatalf("audit event = %+v", events[index])
		}
	}
	if events[0].Extensions["binding"] != "revision" || events[0].Extensions["expected_revision"] != "1" || events[0].Extensions["on_behalf_of"] != "onur" {
		t.Fatalf("revision audit = %+v", events[0])
	}
	if events[1].Extensions["binding"] != "revision" || events[1].Approver != "operator:telegram" || events[1].Extensions["on_behalf_of"] != "telegram:42" {
		t.Fatalf("on-behalf-of audit = %+v", events[1])
	}
}

func TestServiceRejectsInvalidInputAndValidatorFailure(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{}); err == nil {
		t.Fatal("New(nil) succeeded")
	}
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	rejected := errors.New("plan invalid")
	service, _ := New(Options{Store: store, Validator: ActivationValidatorFunc(func(context.Context, grants.Grant, grants.ApprovalConstraints) error { return rejected })})
	created := create(t, store, "request")
	if _, err := service.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "decision", Constraints: &operatorv1.Constraints{DurationSeconds: -1},
	}); !errors.Is(err, grants.ErrInvalidCommand) {
		t.Fatalf("invalid constraint error = %v", err)
	}
	if _, err := service.Decide(t.Context(), created.Grant.ID, operatorv1.ActionApprove, "operator:onur", operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "approve",
	}); !errors.Is(err, rejected) {
		t.Fatalf("validator error = %v", err)
	}
	denied, err := service.Decide(t.Context(), created.Grant.ID, operatorv1.ActionDeny, "operator:onur", operatorv1.Decision{
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "deny",
	})
	if err != nil || denied.Grant.Status != grants.StatusDenied {
		t.Fatalf("deny Decide() = %+v, %v", denied, err)
	}
}

func TestApprovalValidationAndCommitAreAtomic(t *testing.T) {
	t.Parallel()
	store := grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})
	created := create(t, store, "atomic")
	validationStarted := make(chan struct{})
	releaseValidation := make(chan struct{})
	service, err := New(Options{Store: store, Validator: ActivationValidatorFunc(func(context.Context, grants.Grant, grants.ApprovalConstraints) error {
		close(validationStarted)
		<-releaseValidation
		return nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	decide := func(action operatorv1.Action, done chan<- error) {
		_, err := service.Decide(t.Context(), created.Grant.ID, action, "operator:onur", operatorv1.Decision{
			ExpectedRevision: created.Grant.Revision, IdempotencyKey: "atomic-" + string(action),
		})
		done <- err
	}
	approveDone := make(chan error, 1)
	go decide(operatorv1.ActionApprove, approveDone)
	<-validationStarted
	denyDone := make(chan error, 1)
	go decide(operatorv1.ActionDeny, denyDone)
	select {
	case err := <-denyDone:
		t.Fatalf("concurrent denial completed during activation validation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseValidation)
	if err := <-approveDone; err != nil {
		t.Fatalf("approve Decide() error = %v", err)
	}
	if err := <-denyDone; !errors.Is(err, grants.ErrRevisionConflict) {
		t.Fatalf("deny Decide() error = %v, want ErrRevisionConflict", err)
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
