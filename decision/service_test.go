package decision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/audit"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorv1"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/usebudget"
)

func TestServiceUsesValidatorForRevisionAndTokenApproval(t *testing.T) {
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
	approved, err := service.ApproveToken(t.Context(), second.Grant.ID, second.DecisionToken, "telegram:onur", notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2})
	if err != nil || approved.Status != grants.StatusActive || calls != 2 {
		t.Fatalf("ApproveToken() = %+v, %v calls=%d", approved, err, calls)
	}
}

func TestServiceAuditsRevisionAndTokenBindings(t *testing.T) {
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
	second := create(t, store, "audit-token")
	if _, err := service.ApproveToken(t.Context(), second.Grant.ID, second.DecisionToken, "telegram:42", notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2}); err != nil {
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
	if events[1].Extensions["binding"] != "token:telegram" || events[1].Approver != "telegram:42" {
		t.Fatalf("token audit = %+v", events[1])
	}
	if bytes.Contains(output.Bytes(), []byte(second.DecisionToken)) {
		t.Fatal("audit output leaked a decision token")
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
	service, err := New(Options{Store: store, Validator: ActivationValidatorFunc(func(context.Context, grants.Grant, grants.ApprovalConstraints) error {
		close(validationStarted)
		<-releaseValidation
		return nil
	})})
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
