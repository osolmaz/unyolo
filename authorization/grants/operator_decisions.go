package grants

import (
	"errors"
	"unicode"
	"unicode/utf8"

	"github.com/osolmaz/unyolo/authorization/activation"
)

const maxApproverBytes = 200

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

func (s *Store) prepareOperatorDecision() (fileData, map[string]Grant, uint64, bool, error) {
	data, err := s.load()
	if err != nil {
		return fileData{}, nil, 0, false, activation.New(activation.CodeStorageUnavailable, err)
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
		return activation.New(activation.CodeStorageUnavailable, err)
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return nil
}

func grantSnapshotsWith(before map[string]Grant, current Grant) map[string]Grant {
	copy := make(map[string]Grant, len(before))
	for id, grant := range before {
		copy[id] = grant
	}
	copy[current.ID] = current
	return copy
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
