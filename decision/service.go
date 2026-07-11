// Package decision owns the single BrokerKit decision path used by every transport.
package decision

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorv1"
)

// ActivationValidator is the provider-owned fail-closed approval check.
type ActivationValidator interface {
	ValidateActivation(context.Context, grants.Grant, grants.ApprovalConstraints) error
}

// ActivationValidatorFunc adapts a function to ActivationValidator.
type ActivationValidatorFunc func(context.Context, grants.Grant, grants.ApprovalConstraints) error

func (f ActivationValidatorFunc) ValidateActivation(ctx context.Context, grant grants.Grant, constraints grants.ApprovalConstraints) error {
	return f(ctx, grant, constraints)
}

// Service is the only first-party entry point for operator decisions.
type Service struct {
	store     *grants.Store
	validator ActivationValidator
}

func New(store *grants.Store, validator ActivationValidator) (*Service, error) {
	if store == nil {
		return nil, errors.New("grant store is required")
	}
	return &Service{store: store, validator: validator}, nil
}

// Decide applies one revision-bound Operator V1 decision.
func (s *Service) Decide(ctx context.Context, id string, action operatorv1.Action, actor string, command operatorv1.Decision) (grants.OperatorDecisionResult, error) {
	constraints, err := normalizeConstraints(command.Constraints)
	if err != nil {
		return grants.OperatorDecisionResult{}, err
	}
	decision := grants.OperatorDecision{
		ID: id, Action: grants.DecisionAction(action), Approver: actor,
		OnBehalfOf: command.OnBehalfOf, ExpectedRevision: command.ExpectedRevision,
		IdempotencyKey: command.IdempotencyKey, Reason: command.DecisionReason,
		Constraints: constraints,
	}
	return s.store.ApplyOperatorDecision(ctx, decision, s.validate)
}

func normalizeConstraints(value *operatorv1.Constraints) (grants.ApprovalConstraints, error) {
	if value == nil {
		return grants.ApprovalConstraints{}, nil
	}
	if value.DurationSeconds < 0 || value.DurationSeconds > math.MaxInt64/int64(time.Second) || value.MaxUses < 0 {
		return grants.ApprovalConstraints{}, grants.ErrInvalidCommand
	}
	return grants.ApprovalConstraints{Duration: time.Duration(value.DurationSeconds) * time.Second, MaxUses: value.MaxUses}, nil
}

func (s *Service) validate(ctx context.Context, grant grants.Grant, constraints grants.ApprovalConstraints) error {
	if s.validator == nil {
		return nil
	}
	return s.validator.ValidateActivation(ctx, grant, constraints)
}

// ApproveToken applies a single-use notification-channel approval through the same validator.
func (s *Service) ApproveToken(ctx context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	grant, err := s.store.Get(id)
	if err != nil {
		return grants.Grant{}, err
	}
	if err := s.validate(ctx, grant, grants.ApprovalConstraints{}); err != nil {
		return grants.Grant{}, err
	}
	return s.store.ApproveWithNotification(id, token, actor, grants.MessageRef(ref))
}

// DenyToken applies a single-use notification-channel denial.
func (s *Service) DenyToken(_ context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	return s.store.DenyWithNotification(id, token, actor, grants.MessageRef(ref))
}
