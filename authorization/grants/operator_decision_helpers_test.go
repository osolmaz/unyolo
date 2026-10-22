package grants

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
)

type DecisionCommand struct {
	ID               string
	Approver         string
	ExpectedRevision int64
}

type ApproveCommand struct {
	DecisionCommand
	Duration time.Duration
	MaxUses  int
}

var testDecisionSequence atomic.Uint64

func (s *Store) OperatorApprove(command ApproveCommand) (Grant, error) {
	return s.applyTestOperatorDecision(command.DecisionCommand, ActionApprove, ApprovalConstraints{Duration: command.Duration, MaxUses: usebudget.Limit(command.MaxUses)})
}

func (s *Store) OperatorDeny(command DecisionCommand) (Grant, error) {
	return s.applyTestOperatorDecision(command, ActionDeny, ApprovalConstraints{})
}

func (s *Store) OperatorRevoke(command DecisionCommand) (Grant, error) {
	return s.applyTestOperatorDecision(command, ActionRevoke, ApprovalConstraints{})
}

func (s *Store) applyTestOperatorDecision(command DecisionCommand, action DecisionAction, constraints ApprovalConstraints) (Grant, error) {
	result, err := s.ApplyOperatorDecision(context.Background(), OperatorDecision{
		ID: command.ID, Action: action, Approver: command.Approver,
		ExpectedRevision: command.ExpectedRevision,
		IdempotencyKey:   fmt.Sprintf("test-%d", testDecisionSequence.Add(1)), Constraints: constraints,
	}, nil)
	return result.Grant, err
}

func approveTestGrant(t *testing.T, store *Store, id string) Grant {
	t.Helper()
	current, err := store.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.OperatorApprove(ApproveCommand{DecisionCommand: DecisionCommand{ID: id, Approver: "operator", ExpectedRevision: current.Revision}})
	if err != nil {
		t.Fatal(err)
	}
	return approved
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
		MaxUses:         usebudget.Limit(maxUses),
	}
}

func approveForTest(store *Store, id, approver string) (Grant, error) {
	return decideForTest(store, id, approver, ActionApprove)
}

func denyForTest(store *Store, id, approver string) (Grant, error) {
	return decideForTest(store, id, approver, ActionDeny)
}

func decideForTest(store *Store, id, approver string, action DecisionAction) (Grant, error) {
	current, err := store.Get(id)
	if err != nil {
		return Grant{}, err
	}
	return store.applyTestOperatorDecision(DecisionCommand{ID: id, Approver: approver, ExpectedRevision: current.Revision}, action, ApprovalConstraints{})
}
