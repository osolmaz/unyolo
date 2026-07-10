package grants

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxApproverBytes       = 200
	maxDecisionReasonBytes = 2_000
)

var (
	ErrRevisionConflict = errors.New("grant revision conflict")
	ErrInvalidCommand   = errors.New("invalid operator command")
)

// RevisionConflictError returns the authoritative state after a stale command.
type RevisionConflictError struct {
	Current Grant
}

func (e *RevisionConflictError) Error() string { return ErrRevisionConflict.Error() }
func (e *RevisionConflictError) Unwrap() error { return ErrRevisionConflict }

// DecisionCommand identifies and bounds one operator transition.
type DecisionCommand struct {
	ID               string
	Approver         string
	ExpectedRevision int64
	ExpectedStatus   Status
	Reason           string
}

// ApproveCommand may only shorten the duration and use count requested by the client.
type ApproveCommand struct {
	DecisionCommand
	Duration time.Duration
	MaxUses  int
}

// OperatorApprove activates a canonical pending request.
func (s *Store) OperatorApprove(command ApproveCommand) (Grant, error) {
	return s.operatorDecision(command.DecisionCommand, func(grant Grant) (Grant, error) {
		if grant.Status != StatusPending {
			return grant, ErrNotPending
		}
		if command.Duration < 0 || command.Duration > grant.Duration {
			return grant, fmt.Errorf("%w: approved duration exceeds requested duration", ErrInvalidCommand)
		}
		if command.MaxUses < 0 || command.MaxUses > grant.MaxUses {
			return grant, fmt.Errorf("%w: approved max uses exceeds requested max uses", ErrInvalidCommand)
		}
		if command.Duration > 0 {
			grant.Duration = command.Duration
		}
		if command.MaxUses > 0 {
			grant.MaxUses = command.MaxUses
		}
		grant.Status = StatusActive
		grant.DecidedAt = s.opts.Now().UTC()
		grant.DecidedBy = command.Approver
		grant.DecisionReason = command.Reason
		grant.ExpiresAt = grant.DecidedAt.Add(s.durationFromGrant(grant))
		grant.NotificationDeliveryUnresolved = false
		return grant, nil
	})
}

// OperatorDeny rejects a canonical pending request.
func (s *Store) OperatorDeny(command DecisionCommand) (Grant, error) {
	return s.operatorPendingTerminal(command, StatusDenied)
}

// OperatorCancel cancels a canonical pending request.
func (s *Store) OperatorCancel(command DecisionCommand) (Grant, error) {
	return s.operatorPendingTerminal(command, StatusCanceled)
}

func (s *Store) operatorPendingTerminal(command DecisionCommand, status Status) (Grant, error) {
	return s.operatorDecision(command, func(grant Grant) (Grant, error) {
		if grant.Status != StatusPending {
			return grant, ErrNotPending
		}
		grant.Status = status
		grant.DecidedAt = s.opts.Now().UTC()
		grant.DecidedBy = command.Approver
		grant.DecisionReason = command.Reason
		grant.NotificationDeliveryUnresolved = false
		return grant, nil
	})
}

// OperatorRevoke closes a canonical active grant.
func (s *Store) OperatorRevoke(command DecisionCommand) (Grant, error) {
	return s.operatorDecision(command, func(grant Grant) (Grant, error) {
		if grant.Status != StatusActive {
			return grant, ErrNotActive
		}
		grant.Status = StatusRevoked
		grant.DecidedAt = s.opts.Now().UTC()
		grant.DecidedBy = command.Approver
		grant.DecisionReason = command.Reason
		return grant, nil
	})
}

func (s *Store) operatorDecision(command DecisionCommand, mutate func(Grant) (Grant, error)) (Grant, error) {
	command, err := normalizeDecisionCommand(command)
	if err != nil {
		return Grant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, before, eventSequence, lifecycleChanged, err := s.prepareOperatorDecision()
	if err != nil {
		return Grant{}, err
	}
	index, current, err := findGrant(data.Grants, command.ID)
	if err != nil {
		return Grant{}, s.saveLifecycleOnError(data, eventSequence, lifecycleChanged, err)
	}
	if decisionConflicts(command, current) {
		err := &RevisionConflictError{Current: current}
		return current, s.saveLifecycleOnError(data, eventSequence, lifecycleChanged, err)
	}
	updated, err := mutate(current)
	if err != nil {
		return current, s.saveLifecycleOnError(data, eventSequence, lifecycleChanged, err)
	}
	data.Grants[index] = updated
	s.reconcileOperatorMutation(&data, before, current, lifecycleChanged)
	if err := s.persistOperatorDecision(data, eventSequence); err != nil {
		return Grant{}, err
	}
	return data.Grants[index], nil
}

func (s *Store) prepareOperatorDecision() (fileData, map[string]Grant, uint64, bool, error) {
	data, err := s.load()
	if err != nil {
		return fileData{}, nil, 0, false, err
	}
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	lifecycleChanged := s.prepareLifecycle(&data)
	if lifecycleChanged {
		s.reconcileLifecycle(&data, before)
	}
	return data, before, eventSequence, lifecycleChanged, nil
}

func (s *Store) reconcileOperatorMutation(data *fileData, before map[string]Grant, current Grant, lifecycleChanged bool) {
	if lifecycleChanged {
		s.reconcileLifecycle(data, grantSnapshotsWith(before, current))
		return
	}
	s.reconcileLifecycle(data, before)
}

func (s *Store) persistOperatorDecision(data fileData, eventSequence uint64) error {
	if err := s.save(data); err != nil {
		return err
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return nil
}

func decisionConflicts(command DecisionCommand, current Grant) bool {
	return command.ExpectedRevision != current.Revision ||
		(command.ExpectedStatus != "" && command.ExpectedStatus != current.Status)
}

func (s *Store) saveLifecycleOnError(data fileData, eventSequence uint64, changed bool, commandErr error) error {
	if !changed {
		return commandErr
	}
	if err := s.save(data); err != nil {
		return errors.Join(commandErr, err)
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return commandErr
}

func grantSnapshotsWith(before map[string]Grant, current Grant) map[string]Grant {
	copy := make(map[string]Grant, len(before))
	for id, grant := range before {
		copy[id] = grant
	}
	copy[current.ID] = current
	return copy
}

func normalizeDecisionCommand(command DecisionCommand) (DecisionCommand, error) {
	command.ID = strings.TrimSpace(command.ID)
	command.Approver = strings.TrimSpace(command.Approver)
	command.Reason = strings.TrimSpace(command.Reason)
	if command.ID == "" || command.Approver == "" || command.ExpectedRevision < 1 {
		return DecisionCommand{}, fmt.Errorf("%w: id, approver, and positive expected revision are required", ErrInvalidCommand)
	}
	if !safeOperatorIdentity(command.Approver) || !safeOperatorText(command.Reason, maxDecisionReasonBytes) {
		return DecisionCommand{}, fmt.Errorf("%w: approver or reason contains unsupported text", ErrInvalidCommand)
	}
	return command, nil
}

func safeOperatorIdentity(value string) bool {
	if len(value) > maxApproverBytes || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func safeOperatorText(value string, maxBytes int) bool {
	if len(value) > maxBytes || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) && char != '\n' && char != '\t' {
			return false
		}
	}
	return true
}
