package grants

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/osolmaz/unyolo/authorization/budget"
	"time"
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
