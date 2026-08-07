package grants

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/authorization/activation"
	"github.com/osolmaz/unyolo/authorization/budget"
)

// DecisionAction is one Operator V1 lifecycle transition.
type DecisionAction string

const (
	ActionApprove DecisionAction = "approve"
	ActionDeny    DecisionAction = "deny"
	ActionRevoke  DecisionAction = "revoke"
)

var (
	ErrInvalidTransition  = errors.New("invalid grant transition")
	ErrConstraintExceeded = errors.New("approval constraint exceeded")
)

// ApprovalConstraints contains provider-neutral approval narrowing.
type ApprovalConstraints struct {
	Duration         time.Duration
	MaxUses          usebudget.Limit
	MaxUsesSpecified bool
}

// OperatorDecision is a normalized revision-bound Operator V1 command.
type OperatorDecision struct {
	ID               string
	Action           DecisionAction
	Approver         string
	OnBehalfOf       string
	ExpectedRevision int64
	IdempotencyKey   string
	Constraints      ApprovalConstraints
	DecisionToken    string
	Notification     *MessageRef
	CorrelationID    string `json:"-"`
}

// ActivationCheck runs under the grant-store lock before approval commits.
type ActivationCheck func(context.Context, Grant, ApprovalConstraints) error

// OperatorDecisionResult reports the originally committed representation on replay.
type OperatorDecisionResult struct {
	Grant       Grant
	Previous    Grant
	EventCursor string
	Replay      bool
}

type decisionRecord struct {
	Scope            string    `json:"scope"`
	CommandHash      string    `json:"command_hash"`
	Result           Grant     `json:"result"`
	Previous         Grant     `json:"previous"`
	EventCursor      string    `json:"event_cursor"`
	FailureCode      string    `json:"failure_code,omitempty"`
	FailureReference string    `json:"failure_reference,omitempty"`
	CommittedAt      time.Time `json:"committed_at"`
	resultJSON       []byte
	previousJSON     []byte
}

// ApplyOperatorDecision atomically validates and commits one revision-bound decision.
func (s *Store) ApplyOperatorDecision(ctx context.Context, command OperatorDecision, validate ActivationCheck) (OperatorDecisionResult, error) {
	command, err := normalizeOperatorDecision(command)
	if err != nil {
		return OperatorDecisionResult{}, err
	}
	hash := hashOperatorDecision(command)
	scope := decisionScope(command)

	s.mu.Lock()
	defer s.mu.Unlock()
	data, before, eventSequence, lifecycleChanged, err := s.prepareOperatorDecision()
	if err != nil {
		return OperatorDecisionResult{}, err
	}
	if replay, found, replayErr := replayOperatorDecision(data.DecisionRecords, scope, hash); found {
		return replay, s.saveDecisionError(data, eventSequence, lifecycleChanged, replayErr)
	}
	index, current, err := findGrant(data.Grants, command.ID)
	if err != nil {
		return OperatorDecisionResult{}, s.saveDecisionError(data, eventSequence, lifecycleChanged, err)
	}
	if command.ExpectedRevision != current.Revision {
		err := &RevisionConflictError{Current: current}
		return OperatorDecisionResult{Grant: current, Previous: current}, s.saveDecisionError(data, eventSequence, lifecycleChanged, err)
	}
	updated, decisionErr := s.applyDecisionMutation(ctx, current, command, validate)
	if decisionErr != nil && updated.Status != StatusFailed {
		return OperatorDecisionResult{Grant: current, Previous: current}, s.saveDecisionError(data, eventSequence, lifecycleChanged, decisionErr)
	}
	data.Grants[index] = updated
	s.reconcileOperatorMutation(&data, before, current, lifecycleChanged)
	result := data.Grants[index]
	eventCursor := currentEventCursor(data)
	record := decisionRecord{
		Scope: scope, CommandHash: hash, Result: result, Previous: current, EventCursor: eventCursor, CommittedAt: s.opts.Now().UTC(),
	}
	if failure, ok := activation.As(decisionErr); ok {
		record.FailureCode = string(failure.Code)
		record.FailureReference = result.FailureReference
	}
	data.DecisionRecords = append(data.DecisionRecords, record)
	if err := s.persistOperatorDecision(data, eventSequence); err != nil {
		return OperatorDecisionResult{}, err
	}
	return OperatorDecisionResult{Grant: result, Previous: current, EventCursor: eventCursor}, decisionErr
}

func currentEventCursor(data fileData) string {
	if data.NextEvent <= 1 {
		return ""
	}
	return encodeEventCursor(data.NextEvent - 1)
}

func (s *Store) applyDecisionMutation(ctx context.Context, grant Grant, command OperatorDecision, validate ActivationCheck) (Grant, error) {
	now := s.opts.Now().UTC()
	if command.DecisionToken != "" && !decisionTokenMatches(grant.DecisionTokenVerifier, command.DecisionToken) {
		return grant, ErrInvalidDecisionToken
	}
	if command.Notification != nil {
		if err := validateMessageRefIntegrity(*command.Notification); err != nil {
			if grant.Status != StatusPending {
				return grant, ErrNotPending
			}
			return failedActivationGrant(grant, command, now, err), err
		}
	}
	updated, err := s.applyDecisionAction(ctx, grant, command, validate, now)
	if err != nil {
		if failure, ok := terminalActivationFailure(err); ok {
			return failedActivationGrant(grant, command, now, failure), failure
		}
		return grant, err
	}
	updated.DecidedAt = now
	updated.DecidedBy = command.Approver
	updated.DecidedOnBehalfOf = command.OnBehalfOf
	updated.NotificationDeliveryUnresolved = false
	updated, _ = attachDecisionNotification(updated, command.Notification)
	return updated, nil
}

func terminalActivationFailure(err error) (*activation.Failure, bool) {
	failure, ok := activation.As(err)
	if !ok || failure.Retryable {
		return nil, false
	}
	switch failure.Code {
	case activation.CodeInvalidNotification, activation.CodePlanUnavailable, activation.CodePlanMismatch,
		activation.CodeCredentialChanged, activation.CodeCredentialInsufficient:
		return failure, true
	default:
		return nil, false
	}
}

func failedActivationGrant(grant Grant, command OperatorDecision, now time.Time, err error) Grant {
	failure := activation.Classify(err)
	grant.Status = StatusFailed
	grant.DecidedAt = now
	grant.DecidedBy = command.Approver
	grant.DecidedOnBehalfOf = command.OnBehalfOf
	grant.FailureCode = string(failure.Code)
	grant.FailureReference = command.CorrelationID
	grant.FailedAt = now
	grant.NotificationDeliveryUnresolved = false
	if failure.Code != activation.CodeInvalidNotification {
		grant, _ = attachDecisionNotification(grant, command.Notification)
	}
	return grant
}

func (s *Store) applyDecisionAction(ctx context.Context, grant Grant, command OperatorDecision, validate ActivationCheck, now time.Time) (Grant, error) {
	if command.Action == ActionApprove {
		return applyApprovalMutation(ctx, grant, command.Constraints, validate, now)
	}
	return applyTerminalDecisionAction(grant, command.Action)
}

func applyTerminalDecisionAction(grant Grant, action DecisionAction) (Grant, error) {
	status, required, valid := terminalDecisionTransition(action)
	if !valid {
		return grant, ErrInvalidCommand
	}
	if grant.Status != required {
		return grant, ErrInvalidTransition
	}
	grant.Status = status
	return grant, nil
}

func terminalDecisionTransition(action DecisionAction) (Status, Status, bool) {
	switch action {
	case ActionDeny:
		return StatusDenied, StatusPending, true
	case ActionRevoke:
		return StatusRevoked, StatusActive, true
	default:
		return "", "", false
	}
}

func applyApprovalMutation(ctx context.Context, grant Grant, constraints ApprovalConstraints, validate ActivationCheck, now time.Time) (Grant, error) {
	if grant.Status != StatusPending {
		return grant, ErrInvalidTransition
	}
	requestedDuration, requestedMaxUses := requestedApprovalBounds(grant)
	if !validApprovalConstraints(constraints, requestedDuration, requestedMaxUses) {
		return grant, ErrConstraintExceeded
	}
	if validate != nil {
		if err := validate(ctx, grant, constraints); err != nil {
			return grant, err
		}
	}
	grant = applyApprovalConstraints(grant, constraints)
	grant.Status = StatusActive
	grant.ExpiresAt = now.Add(grant.Duration)
	return grant, nil
}

func requestedApprovalBounds(grant Grant) (time.Duration, usebudget.Limit) {
	duration := grant.RequestedDuration
	if duration <= 0 {
		duration = grant.Duration
	}
	maxUses := grant.RequestedMaxUses
	if maxUses < 0 {
		maxUses = grant.MaxUses
	}
	return duration, maxUses
}

func validApprovalConstraints(constraints ApprovalConstraints, duration time.Duration, maxUses usebudget.Limit) bool {
	if constraints.Duration < 0 || constraints.Duration > duration || constraints.MaxUses < 0 {
		return false
	}
	if !constraintUseLimitSpecified(constraints) {
		return true
	}
	if constraints.MaxUses.IsUnlimited() {
		return maxUses.IsUnlimited()
	}
	return maxUses.IsUnlimited() || constraints.MaxUses <= maxUses
}

func applyApprovalConstraints(grant Grant, constraints ApprovalConstraints) Grant {
	if constraints.Duration > 0 {
		grant.Duration = constraints.Duration
	}
	if constraintUseLimitSpecified(constraints) {
		grant.MaxUses = constraints.MaxUses
	}
	return grant
}

func normalizeOperatorDecision(command OperatorDecision) (OperatorDecision, error) {
	command.ID = strings.TrimSpace(command.ID)
	command.Approver = strings.TrimSpace(command.Approver)
	command.OnBehalfOf = strings.TrimSpace(command.OnBehalfOf)
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	command.DecisionToken = strings.TrimSpace(command.DecisionToken)
	command.CorrelationID = strings.TrimSpace(command.CorrelationID)
	if !operatorDecisionRequired(command) {
		return OperatorDecision{}, fmt.Errorf("%w: id, approver, revision, and idempotency key are required", ErrInvalidCommand)
	}
	if !validOperatorDecisionText(command) || !validOperatorAction(command.Action) {
		return OperatorDecision{}, ErrInvalidCommand
	}
	if !validOperatorConstraints(command) {
		return OperatorDecision{}, ErrInvalidCommand
	}
	if err := validateOperatorNotification(command); err != nil {
		return OperatorDecision{}, ErrInvalidCommand
	}
	return command, nil
}

func validOperatorConstraints(command OperatorDecision) bool {
	return command.Action == ActionApprove ||
		(command.Constraints.Duration == 0 && !constraintUseLimitSpecified(command.Constraints))
}

func validateOperatorNotification(command OperatorDecision) error {
	if (command.DecisionToken == "") != (command.Notification == nil) {
		return ErrInvalidCommand
	}
	if command.Notification == nil {
		return nil
	}
	if command.Action == ActionRevoke {
		return ErrInvalidCommand
	}
	return validateMessageRefShape(*command.Notification)
}

func constraintUseLimitSpecified(constraints ApprovalConstraints) bool {
	return constraints.MaxUsesSpecified || constraints.MaxUses.IsFinite()
}

func operatorDecisionRequired(command OperatorDecision) bool {
	return command.ID != "" && command.Approver != "" && command.ExpectedRevision >= 1 && command.IdempotencyKey != ""
}

func validOperatorDecisionText(command OperatorDecision) bool {
	return validOperatorDecisionIdentities(command) && validOperatorDecisionReferences(command)
}

func validOperatorDecisionIdentities(command OperatorDecision) bool {
	return len(command.IdempotencyKey) <= 200 && safeOperatorIdentity(command.IdempotencyKey) &&
		safeOperatorIdentity(command.Approver) && (command.OnBehalfOf == "" || safeOperatorIdentity(command.OnBehalfOf))
}

func validOperatorDecisionReferences(command OperatorDecision) bool {
	return len(command.DecisionToken) <= 200 && (command.DecisionToken == "" || safeOperatorIdentity(command.DecisionToken)) &&
		len(command.CorrelationID) <= 128 && (command.CorrelationID == "" || safeOperatorIdentity(command.CorrelationID))
}

func validOperatorAction(action DecisionAction) bool {
	return slices.Contains([]DecisionAction{ActionApprove, ActionDeny, ActionRevoke}, action)
}

func hashOperatorDecision(command OperatorDecision) string {
	encoded, _ := json.Marshal(command)
	digest := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func decisionScope(command OperatorDecision) string {
	return command.ID + "\x00" + string(command.Action) + "\x00" + command.IdempotencyKey
}

func findDecisionRecord(records []decisionRecord, scope string) (decisionRecord, bool) {
	for _, record := range records {
		if record.Scope == scope {
			return record, true
		}
	}
	return decisionRecord{}, false
}

func replayOperatorDecision(records []decisionRecord, scope string, hash string) (OperatorDecisionResult, bool, error) {
	record, found := findDecisionRecord(records, scope)
	if !found {
		return OperatorDecisionResult{}, false, nil
	}
	if record.CommandHash != hash {
		return OperatorDecisionResult{}, true, ErrIdempotencyConflict
	}
	result := OperatorDecisionResult{Grant: record.Result, Previous: record.Previous, EventCursor: record.EventCursor, Replay: true}
	if record.FailureCode != "" {
		return result, true, activation.New(activation.Code(record.FailureCode), nil)
	}
	return result, true, nil
}

func (s *Store) saveDecisionError(data fileData, eventSequence uint64, lifecycleChanged bool, commandErr error) error {
	if lifecycleChanged {
		if err := s.persistOperatorDecision(data, eventSequence); err != nil {
			return errors.Join(commandErr, err)
		}
	}
	return commandErr
}
