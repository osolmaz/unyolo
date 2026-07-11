// Package decision owns the single BrokerKit decision path used by every transport.
package decision

import (
	"context"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/osolmaz/brokerkit/audit"
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
	broker    string
	audit     audit.Recorder
}

// Options assembles the transport-independent decision path.
type Options struct {
	Store     *grants.Store
	Validator ActivationValidator
	Broker    string
	Audit     audit.Recorder
}

// Result is a committed revision-bound decision and its export diagnostic.
type Result struct {
	grants.OperatorDecisionResult
	AuditExportFailed bool
}

func New(options Options) (*Service, error) {
	if options.Store == nil {
		return nil, errors.New("grant store is required")
	}
	return &Service{store: options.Store, validator: options.Validator, broker: options.Broker, audit: options.Audit}, nil
}

// Decide applies one revision-bound Operator V1 decision.
func (s *Service) Decide(ctx context.Context, id string, action operatorv1.Action, actor string, command operatorv1.Decision) (Result, error) {
	constraints, err := normalizeConstraints(command.Constraints)
	if err != nil {
		current, _ := s.store.Get(id)
		_ = s.record(current, current, string(action), actor, command.OnBehalfOf, command.DecisionReason, "revision", "", false, command.ExpectedRevision, grants.ApprovalConstraints{}, err)
		return Result{}, err
	}
	decision := grants.OperatorDecision{
		ID: id, Action: grants.DecisionAction(action), Approver: actor,
		OnBehalfOf: command.OnBehalfOf, ExpectedRevision: command.ExpectedRevision,
		IdempotencyKey: command.IdempotencyKey, Reason: command.DecisionReason,
		Constraints: constraints,
	}
	result, decisionErr := s.store.ApplyOperatorDecision(ctx, decision, s.validate)
	auditPrevious, auditCurrent := result.Previous, result.Grant
	if auditPrevious.ID == "" {
		auditPrevious, _ = s.store.Get(id)
		auditCurrent = auditPrevious
	}
	auditErr := s.record(auditPrevious, auditCurrent, string(action), actor, command.OnBehalfOf, command.DecisionReason, "revision", result.EventCursor, result.Replay, command.ExpectedRevision, constraints, decisionErr)
	return Result{OperatorDecisionResult: result, AuditExportFailed: auditErr != nil}, decisionErr
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
	result, err := s.store.ApproveWithNotificationValidated(ctx, id, token, actor, grants.MessageRef(ref), s.validate)
	previous, current := s.tokenAuditGrants(id, result)
	_ = s.record(previous, current, string(grants.ActionApprove), actor, "", "", "token:"+ref.Kind, result.EventCursor, false, 0, grants.ApprovalConstraints{}, err)
	if err != nil && !result.Changed {
		return grants.Grant{}, err
	}
	return result.Grant, err
}

// DenyToken applies a single-use notification-channel denial.
func (s *Service) DenyToken(ctx context.Context, id, token, actor string, ref notify.MessageRef) (grants.Grant, error) {
	result, err := s.store.DenyWithNotificationResult(ctx, id, token, actor, grants.MessageRef(ref))
	previous, current := s.tokenAuditGrants(id, result)
	_ = s.record(previous, current, string(grants.ActionDeny), actor, "", "", "token:"+ref.Kind, result.EventCursor, false, 0, grants.ApprovalConstraints{}, err)
	if err != nil && !result.Changed {
		return grants.Grant{}, err
	}
	return result.Grant, err
}

func (s *Service) tokenAuditGrants(id string, result grants.TokenDecisionResult) (grants.Grant, grants.Grant) {
	if result.Previous.ID != "" {
		return result.Previous, result.Grant
	}
	current, _ := s.store.Get(id)
	return current, current
}

func (s *Service) record(previous, current grants.Grant, action, actor, onBehalfOf, reason, binding, eventCursor string, replay bool, expectedRevision int64, constraints grants.ApprovalConstraints, decisionErr error) error {
	if s.audit == nil {
		return nil
	}
	grant := current
	if grant.ID == "" {
		grant = previous
	}
	extensions := map[string]string{
		"binding":            binding,
		"previous_revision":  strconv.FormatInt(previous.Revision, 10),
		"previous_status":    string(previous.Status),
		"current_revision":   strconv.FormatInt(current.Revision, 10),
		"current_status":     string(current.Status),
		"event_cursor":       eventCursor,
		"idempotency_replay": strconv.FormatBool(replay),
		"expected_revision":  strconv.FormatInt(expectedRevision, 10),
		"duration_seconds":   strconv.FormatInt(int64(constraints.Duration/time.Second), 10),
		"max_uses":           strconv.Itoa(constraints.MaxUses),
	}
	if onBehalfOf != "" {
		extensions["on_behalf_of"] = onBehalfOf
	}
	event := audit.Event{
		Broker: s.broker, Client: grant.Client, Operation: grant.Operation, Decision: action,
		Reason: reason, GrantID: grant.ID, Approver: actor, Extensions: extensions,
	}
	if decisionErr != nil {
		event.ErrorCode = decisionErrorCode(decisionErr)
	}
	return s.audit.Record(event)
}

func decisionErrorCode(err error) string {
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return "not_found"
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return "invalid_decision_token"
	case errors.Is(err, grants.ErrIdempotencyConflict):
		return "idempotency_conflict"
	case errors.Is(err, grants.ErrConstraintExceeded):
		return "constraint_exceeded"
	case errors.Is(err, grants.ErrInvalidTransition), errors.Is(err, grants.ErrNotPending), errors.Is(err, grants.ErrNotActive):
		return "invalid_transition"
	default:
		return "decision_failed"
	}
}
