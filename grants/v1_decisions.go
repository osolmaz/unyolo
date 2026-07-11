package grants

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DecisionAction is one Operator V1 lifecycle transition.
type DecisionAction string

const (
	ActionApprove DecisionAction = "approve"
	ActionDeny    DecisionAction = "deny"
	ActionCancel  DecisionAction = "cancel"
	ActionRevoke  DecisionAction = "revoke"
)

var (
	ErrInvalidTransition  = errors.New("invalid grant transition")
	ErrConstraintExceeded = errors.New("approval constraint exceeded")
)

// ApprovalConstraints contains provider-neutral approval narrowing.
type ApprovalConstraints struct {
	Duration time.Duration
	MaxUses  int
}

// OperatorDecision is a normalized revision-bound Operator V1 command.
type OperatorDecision struct {
	ID               string
	Action           DecisionAction
	Approver         string
	OnBehalfOf       string
	ExpectedRevision int64
	IdempotencyKey   string
	Reason           string
	Constraints      ApprovalConstraints
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
	Scope       string    `json:"scope"`
	CommandHash string    `json:"command_hash"`
	Result      Grant     `json:"result"`
	Previous    Grant     `json:"previous"`
	EventCursor string    `json:"event_cursor"`
	CommittedAt time.Time `json:"committed_at"`
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
	if record, ok := findDecisionRecord(data.DecisionRecords, scope); ok {
		if record.CommandHash != hash {
			return OperatorDecisionResult{}, s.saveDecisionError(data, eventSequence, lifecycleChanged, ErrIdempotencyConflict)
		}
		return OperatorDecisionResult{Grant: record.Result, Previous: record.Previous, EventCursor: record.EventCursor, Replay: true}, s.saveDecisionError(data, eventSequence, lifecycleChanged, nil)
	}
	index, current, err := findGrant(data.Grants, command.ID)
	if err != nil {
		return OperatorDecisionResult{}, s.saveDecisionError(data, eventSequence, lifecycleChanged, err)
	}
	if command.ExpectedRevision != current.Revision {
		err := &RevisionConflictError{Current: current}
		return OperatorDecisionResult{Grant: current, Previous: current}, s.saveDecisionError(data, eventSequence, lifecycleChanged, err)
	}
	updated, err := s.applyDecisionMutation(ctx, current, command, validate)
	if err != nil {
		return OperatorDecisionResult{Grant: current, Previous: current}, s.saveDecisionError(data, eventSequence, lifecycleChanged, err)
	}
	data.Grants[index] = updated
	s.reconcileOperatorMutation(&data, before, current, lifecycleChanged)
	result := data.Grants[index]
	eventCursor := currentEventCursor(data)
	data.DecisionRecords = append(data.DecisionRecords, decisionRecord{
		Scope: scope, CommandHash: hash, Result: result, Previous: current, EventCursor: eventCursor, CommittedAt: s.opts.Now().UTC(),
	})
	if err := s.persistOperatorDecision(data, eventSequence); err != nil {
		return OperatorDecisionResult{}, err
	}
	return OperatorDecisionResult{Grant: result, Previous: current, EventCursor: eventCursor}, nil
}

func currentEventCursor(data fileData) string {
	if data.NextEvent <= 1 {
		return ""
	}
	return encodeEventCursor(data.NextEvent - 1)
}

func (s *Store) applyDecisionMutation(ctx context.Context, grant Grant, command OperatorDecision, validate ActivationCheck) (Grant, error) {
	now := s.opts.Now().UTC()
	switch command.Action {
	case ActionApprove:
		if grant.Status != StatusPending {
			return grant, ErrInvalidTransition
		}
		requestedDuration := grant.RequestedDuration
		if requestedDuration <= 0 {
			requestedDuration = grant.Duration
		}
		requestedMaxUses := grant.RequestedMaxUses
		if requestedMaxUses <= 0 {
			requestedMaxUses = grant.MaxUses
		}
		if command.Constraints.Duration < 0 || command.Constraints.Duration > requestedDuration ||
			command.Constraints.MaxUses < 0 || command.Constraints.MaxUses > requestedMaxUses {
			return grant, ErrConstraintExceeded
		}
		if validate != nil {
			if err := validate(ctx, grant, command.Constraints); err != nil {
				return grant, err
			}
		}
		if command.Constraints.Duration > 0 {
			grant.Duration = command.Constraints.Duration
		}
		if command.Constraints.MaxUses > 0 {
			grant.MaxUses = command.Constraints.MaxUses
		}
		grant.Status = StatusActive
		grant.ExpiresAt = now.Add(grant.Duration)
	case ActionDeny:
		if grant.Status != StatusPending {
			return grant, ErrInvalidTransition
		}
		grant.Status = StatusDenied
	case ActionCancel:
		if grant.Status != StatusPending {
			return grant, ErrInvalidTransition
		}
		grant.Status = StatusCanceled
	case ActionRevoke:
		if grant.Status != StatusActive {
			return grant, ErrInvalidTransition
		}
		grant.Status = StatusRevoked
	default:
		return grant, ErrInvalidCommand
	}
	grant.DecidedAt = now
	grant.DecidedBy = command.Approver
	grant.DecidedOnBehalfOf = command.OnBehalfOf
	grant.DecisionReason = command.Reason
	grant.NotificationDeliveryUnresolved = false
	return grant, nil
}

func normalizeOperatorDecision(command OperatorDecision) (OperatorDecision, error) {
	command.ID = strings.TrimSpace(command.ID)
	command.Approver = strings.TrimSpace(command.Approver)
	command.OnBehalfOf = strings.TrimSpace(command.OnBehalfOf)
	command.IdempotencyKey = strings.TrimSpace(command.IdempotencyKey)
	command.Reason = strings.TrimSpace(command.Reason)
	if command.ID == "" || command.Approver == "" || command.ExpectedRevision < 1 || command.IdempotencyKey == "" {
		return OperatorDecision{}, fmt.Errorf("%w: id, approver, revision, and idempotency key are required", ErrInvalidCommand)
	}
	if len(command.IdempotencyKey) > 200 || !safeOperatorIdentity(command.IdempotencyKey) ||
		!safeOperatorIdentity(command.Approver) ||
		(command.OnBehalfOf != "" && !safeOperatorIdentity(command.OnBehalfOf)) ||
		!safeOperatorText(command.Reason, maxDecisionReasonBytes) {
		return OperatorDecision{}, ErrInvalidCommand
	}
	switch command.Action {
	case ActionApprove, ActionDeny, ActionCancel, ActionRevoke:
	default:
		return OperatorDecision{}, ErrInvalidCommand
	}
	if command.Action != ActionApprove && (command.Constraints.Duration != 0 || command.Constraints.MaxUses != 0) {
		return OperatorDecision{}, ErrInvalidCommand
	}
	return command, nil
}

func hashOperatorDecision(command OperatorDecision) string {
	encoded, _ := json.Marshal(command)
	digest := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func decisionScope(command OperatorDecision) string {
	return command.Approver + "\x00" + command.ID + "\x00" + string(command.Action) + "\x00" + command.IdempotencyKey
}

func findDecisionRecord(records []decisionRecord, scope string) (decisionRecord, bool) {
	for _, record := range records {
		if record.Scope == scope {
			return record, true
		}
	}
	return decisionRecord{}, false
}

func (s *Store) saveDecisionError(data fileData, eventSequence uint64, lifecycleChanged bool, commandErr error) error {
	if lifecycleChanged {
		if err := s.persistOperatorDecision(data, eventSequence); err != nil {
			return errors.Join(commandErr, err)
		}
	}
	return commandErr
}
