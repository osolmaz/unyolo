// Package agentops owns the provider-neutral Agent Operations V1 lifecycle.
package agentops

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/state"
)

const (
	maxTargetBytes    = 16 * 1024
	maxArgumentsBytes = 1024 * 1024
	maxResultBytes    = 2 * 1024 * 1024
	maxOperations     = 2048
	terminalRetention = 30 * 24 * time.Hour
)

var (
	ErrNotFound            = errors.New("operation not found")
	ErrIdempotencyConflict = errors.New("operation idempotency conflict")
	ErrInvalidTransition   = errors.New("invalid operation state transition")
	ErrCapacity            = errors.New("operation store capacity reached")
)

type Submit struct {
	Broker         string
	ClientID       string
	IdempotencyKey string
	Operation      string
	Target         json.RawMessage
	Arguments      json.RawMessage
	Reason         string
	Presentation   agentv1.Presentation
	PlanDigest     string
}

type Store struct {
	db     *state.Database
	now    func() time.Time
	newID  func() (string, error)
	mu     sync.Mutex
	signal chan struct{}
}

func New(database *state.Database) *Store {
	return newStore(database, time.Now, randomID)
}

func newStore(database *state.Database, now func() time.Time, newID func() (string, error)) *Store {
	return &Store{db: database, now: now, newID: newID, signal: make(chan struct{})}
}

func (s *Store) Submit(input Submit) (agentv1.Operation, bool, error) {
	return s.submit(input, nil)
}

// SubmitWithPlan atomically persists an immutable execution plan and its
// operation. Replays must provide the same plan digest.
func (s *Store) SubmitWithPlan(input Submit, plan state.PlanRecord) (agentv1.Operation, bool, error) {
	input.PlanDigest = plan.Digest
	return s.submit(input, &plan)
}

func (s *Store) submit(input Submit, plan *state.PlanRecord) (agentv1.Operation, bool, error) {
	normalized, err := normalizeSubmit(input)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.submitLocked(normalized, plan)
}

func (s *Store) submitLocked(input Submit, plan *state.PlanRecord) (agentv1.Operation, bool, error) {
	ctx := context.Background()
	now := s.now().UTC()
	if _, err := s.db.DeleteTerminalOperationsBefore(ctx, now.Add(-terminalRetention)); err != nil {
		return agentv1.Operation{}, false, err
	}
	if existing, found, err := s.findSubmission(ctx, input); err != nil || found {
		return existing, false, err
	}
	return s.createOperation(ctx, input, now, plan)
}

func (s *Store) findSubmission(ctx context.Context, input Submit) (agentv1.Operation, bool, error) {
	record, err := s.db.OperationByIdempotency(ctx, input.ClientID, input.IdempotencyKey)
	if err == nil {
		existing, err := operationFromRecord(record)
		if err != nil {
			return agentv1.Operation{}, false, err
		}
		if !sameSubmission(existing, input) {
			return agentv1.Operation{}, false, ErrIdempotencyConflict
		}
		return clone(existing), true, nil
	}
	if errors.Is(err, state.ErrNotFound) {
		return agentv1.Operation{}, false, nil
	}
	return agentv1.Operation{}, false, err
}

func (s *Store) createOperation(ctx context.Context, input Submit, now time.Time, plan *state.PlanRecord) (agentv1.Operation, bool, error) {
	count, err := s.db.CountOperations(ctx)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if count >= maxOperations {
		return agentv1.Operation{}, false, ErrCapacity
	}
	id, err := s.newID()
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	op := agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: id, Broker: input.Broker, ClientID: input.ClientID,
		IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, Target: input.Target,
		Arguments: input.Arguments, Reason: input.Reason, State: agentv1.StatePending, Revision: 1,
		CreatedAt: now, UpdatedAt: now, Presentation: input.Presentation, PlanDigest: input.PlanDigest,
	}
	var insertErr error
	if plan == nil {
		insertErr = s.db.InsertOperation(ctx, operationRecord(op))
	} else {
		insertErr = s.db.InsertOperationWithPlan(ctx, operationRecord(op), *plan)
	}
	if insertErr != nil {
		return agentv1.Operation{}, false, insertErr
	}
	s.notify()
	return clone(op), true, nil
}

func (s *Store) Get(clientID, id string) (agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(clientID, id)
}

// GetByID returns one operation for trusted in-process lifecycle recovery.
func (s *Store) GetByID(id string) (agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.db.OperationByID(context.Background(), id)
	return storedOperation(record, err)
}

func (s *Store) getLocked(clientID, id string) (agentv1.Operation, error) {
	record, err := s.db.OperationForClient(context.Background(), id, clientID)
	return storedOperation(record, err)
}

func (s *Store) ListUnfinished() ([]agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.db.UnfinishedOperations(context.Background())
	if err != nil {
		return nil, err
	}
	operations := make([]agentv1.Operation, 0, len(records))
	for _, record := range records {
		operation, err := operationFromRecord(record)
		if err != nil {
			return nil, err
		}
		operations = append(operations, operation)
	}
	return operations, nil
}

func (s *Store) SetApproval(id, approvalID string) (agentv1.Operation, error) {
	return s.update(id, func(operation *agentv1.Operation) error {
		if operation.State != agentv1.StatePending || strings.TrimSpace(approvalID) == "" ||
			(operation.ApprovalID != "" && operation.ApprovalID != approvalID) {
			return ErrInvalidTransition
		}
		operation.ApprovalID = approvalID
		return nil
	})
}

func (s *Store) Transition(id string, state agentv1.State) (agentv1.Operation, error) {
	return s.update(id, func(operation *agentv1.Operation) error {
		if !allowedTransition(operation.State, state) {
			return ErrInvalidTransition
		}
		operation.State = state
		return nil
	})
}

func (s *Store) Succeed(id string, result json.RawMessage) (agentv1.Operation, error) {
	result, err := normalizeObjectLimit(result, maxResultBytes)
	if err != nil {
		return agentv1.Operation{}, fmt.Errorf("result: %w", err)
	}
	return s.update(id, func(operation *agentv1.Operation) error {
		if operation.State != agentv1.StateExecuting {
			return ErrInvalidTransition
		}
		operation.State = agentv1.StateSucceeded
		operation.Result = result
		return nil
	})
}

func (s *Store) Fail(id string, state agentv1.State, code, message string) (agentv1.Operation, error) {
	if !validFailureState(state) {
		return agentv1.Operation{}, ErrInvalidTransition
	}
	if !validOperationError(&agentv1.OperationError{Code: code, Message: message}) {
		return agentv1.Operation{}, errors.New("operation error is invalid")
	}
	return s.update(id, func(operation *agentv1.Operation) error {
		if !allowedTransition(operation.State, state) {
			return ErrInvalidTransition
		}
		operation.State = state
		operation.Error = &agentv1.OperationError{Code: code, Message: message}
		return nil
	})
}

func validFailureState(state agentv1.State) bool {
	switch state {
	case agentv1.StateFailed, agentv1.StateDenied, agentv1.StateExpired, agentv1.StateCanceled:
		return true
	default:
		return false
	}
}

func (s *Store) Wait(ctx context.Context, clientID, id string, after int64) (agentv1.Operation, error) {
	for {
		s.mu.Lock()
		operation, err := s.getLocked(clientID, id)
		if err != nil || operation.Revision > after || operation.State.Terminal() {
			s.mu.Unlock()
			return operation, err
		}
		signal := s.signal
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return s.Get(clientID, id)
		case <-signal:
		}
	}
}

func (s *Store) update(id string, change func(*agentv1.Operation) error) (agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.db.OperationByID(context.Background(), id)
	if err != nil {
		return agentv1.Operation{}, mapStateError(err)
	}
	operation, err := operationFromRecord(record)
	if err != nil {
		return agentv1.Operation{}, err
	}
	if err := change(&operation); err != nil {
		return agentv1.Operation{}, err
	}
	expectedRevision := operation.Revision
	operation.Revision++
	operation.UpdatedAt = s.now().UTC()
	if operation.State.Terminal() {
		terminal := operation.UpdatedAt
		operation.TerminalAt = &terminal
	}
	updated, err := s.db.UpdateOperation(context.Background(), operationRecord(operation), expectedRevision)
	if err != nil {
		return agentv1.Operation{}, err
	}
	if !updated {
		return agentv1.Operation{}, ErrInvalidTransition
	}
	s.notify()
	return clone(operation), nil
}

func (s *Store) notify() {
	close(s.signal)
	s.signal = make(chan struct{})
}

func storedOperation(record state.OperationRecord, err error) (agentv1.Operation, error) {
	if err != nil {
		return agentv1.Operation{}, mapStateError(err)
	}
	return operationFromRecord(record)
}

func mapStateError(err error) error {
	if errors.Is(err, state.ErrNotFound) {
		return ErrNotFound
	}
	return err
}

func operationRecord(operation agentv1.Operation) state.OperationRecord {
	presentation, _ := json.Marshal(operation.Presentation)
	var operationError []byte
	if operation.Error != nil {
		operationError, _ = json.Marshal(operation.Error)
	}
	return state.OperationRecord{
		ID: operation.ID, APIVersion: operation.APIVersion, Broker: operation.Broker,
		ClientID: operation.ClientID, IdempotencyKey: operation.IdempotencyKey,
		Operation: operation.Operation, TargetJSON: operation.Target, ArgumentsJSON: operation.Arguments,
		Reason: operation.Reason, State: string(operation.State), Revision: operation.Revision,
		CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt, TerminalAt: operation.TerminalAt,
		ApprovalID: operation.ApprovalID, PresentationJSON: presentation, ResultJSON: operation.Result,
		ErrorJSON: operationError, PlanDigest: operation.PlanDigest,
	}
}

func operationFromRecord(record state.OperationRecord) (agentv1.Operation, error) {
	operation := agentv1.Operation{
		APIVersion: record.APIVersion, ID: record.ID, Broker: record.Broker, ClientID: record.ClientID,
		IdempotencyKey: record.IdempotencyKey, Operation: record.Operation, Target: record.TargetJSON,
		Arguments: record.ArgumentsJSON, Reason: record.Reason, State: agentv1.State(record.State),
		Revision: record.Revision, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
		TerminalAt: record.TerminalAt, ApprovalID: record.ApprovalID, PlanDigest: record.PlanDigest, Result: record.ResultJSON,
	}
	if err := strictjson.Decode(record.PresentationJSON, &operation.Presentation, true); err != nil {
		return agentv1.Operation{}, fmt.Errorf("decode operation presentation: %w", err)
	}
	if len(record.ErrorJSON) > 0 {
		var operationError agentv1.OperationError
		if err := strictjson.Decode(record.ErrorJSON, &operationError, true); err != nil {
			return agentv1.Operation{}, fmt.Errorf("decode operation error: %w", err)
		}
		operation.Error = &operationError
	}
	if err := validateStored(operation); err != nil {
		return agentv1.Operation{}, fmt.Errorf("operation database contains an invalid record: %w", err)
	}
	return operation, nil
}

func normalizeSubmit(input Submit) (Submit, error) {
	input.Broker = strings.TrimSpace(input.Broker)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.Operation = strings.TrimSpace(input.Operation)
	input.Reason = strings.TrimSpace(input.Reason)
	input.Presentation.Title = strings.TrimSpace(input.Presentation.Title)
	input.Presentation.Summary = strings.TrimSpace(input.Presentation.Summary)
	input.PlanDigest = strings.TrimSpace(input.PlanDigest)
	if !validSubmitIdentity(input) {
		return Submit{}, errors.New("operation identity is invalid")
	}
	if !validSubmitPresentation(input) {
		return Submit{}, errors.New("operation presentation is invalid")
	}
	var err error
	input.Target, err = normalizeObjectLimit(input.Target, maxTargetBytes)
	if err != nil {
		return Submit{}, fmt.Errorf("target: %w", err)
	}
	input.Arguments, err = normalizeObjectLimit(input.Arguments, maxArgumentsBytes)
	if err != nil {
		return Submit{}, fmt.Errorf("arguments: %w", err)
	}
	return input, nil
}

func validSubmitIdentity(input Submit) bool {
	return input.Broker != "" && len(input.Broker) <= 64 && input.ClientID != "" && len(input.ClientID) <= 128 &&
		input.IdempotencyKey != "" && len(input.IdempotencyKey) <= 128 && input.Operation != "" && len(input.Operation) <= 128
}

func validSubmitPresentation(input Submit) bool {
	return len(input.Reason) <= 2000 && input.Presentation.Title != "" && len(input.Presentation.Title) <= 160 && len(input.Presentation.Summary) <= 500 &&
		(input.PlanDigest == "" || plandigest.Valid(input.PlanDigest))
}

func normalizeObjectLimit(value json.RawMessage, maximum int) (json.RawMessage, error) {
	if len(value) == 0 || len(value) > maximum {
		return nil, errors.New("JSON object size is invalid")
	}
	if err := strictjson.RejectDuplicateKeys(value); err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, errors.New("value must be a JSON object")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("JSON object has trailing data")
	}
	return json.Marshal(object)
}

func sameSubmission(existing agentv1.Operation, input Submit) bool {
	return existing.Broker == input.Broker && existing.Operation == input.Operation && existing.Reason == input.Reason &&
		existing.Presentation == input.Presentation && existing.PlanDigest == input.PlanDigest &&
		equalJSON(existing.Target, input.Target) && equalJSON(existing.Arguments, input.Arguments)
}

func equalJSON(left, right []byte) bool {
	var compactLeft, compactRight bytes.Buffer
	if json.Compact(&compactLeft, left) != nil || json.Compact(&compactRight, right) != nil {
		return false
	}
	return bytes.Equal(compactLeft.Bytes(), compactRight.Bytes())
}

func allowedTransition(from, to agentv1.State) bool {
	return operationTransitions[from][to]
}

var operationTransitions = map[agentv1.State]map[agentv1.State]bool{
	agentv1.StatePending:   {agentv1.StateApproved: true, agentv1.StateDenied: true, agentv1.StateExpired: true, agentv1.StateCanceled: true, agentv1.StateFailed: true},
	agentv1.StateApproved:  {agentv1.StateExecuting: true, agentv1.StateExpired: true, agentv1.StateCanceled: true, agentv1.StateFailed: true},
	agentv1.StateExecuting: {agentv1.StateSucceeded: true, agentv1.StateFailed: true},
}

func validateStored(operation agentv1.Operation) error {
	if !validStoredIdentity(operation) {
		return errors.New("operation identity or revision is invalid")
	}
	_, err := normalizeSubmit(Submit{Broker: operation.Broker, ClientID: operation.ClientID, IdempotencyKey: operation.IdempotencyKey,
		Operation: operation.Operation, Target: operation.Target, Arguments: operation.Arguments, Reason: operation.Reason, Presentation: operation.Presentation})
	if err != nil {
		return err
	}
	if err := validateStoredLifecycle(operation); err != nil {
		return err
	}
	if len(operation.Result) > 0 {
		if _, err := normalizeObjectLimit(operation.Result, maxResultBytes); err != nil {
			return fmt.Errorf("operation result: %w", err)
		}
	}
	return nil
}

func validStoredIdentity(operation agentv1.Operation) bool {
	return operation.APIVersion == agentv1.APIVersion && strings.TrimSpace(operation.ID) != "" && len(operation.ID) <= 128 &&
		operation.Revision >= 1 && !operation.CreatedAt.IsZero() && !operation.UpdatedAt.IsZero() && !operation.UpdatedAt.Before(operation.CreatedAt)
}

func validateStoredLifecycle(operation agentv1.Operation) error {
	if !validStoredTerminal(operation) {
		return errors.New("operation terminal timestamp is invalid")
	}
	if !validStoredState(operation) {
		return errors.New("operation state or approval is invalid")
	}
	if operation.Error != nil && !validOperationError(operation.Error) {
		return errors.New("operation error is invalid")
	}
	return nil
}

func validStoredTerminal(operation agentv1.Operation) bool {
	return operation.State.Terminal() == (operation.TerminalAt != nil)
}

func validStoredState(operation agentv1.Operation) bool {
	return validState(operation.State) && len(operation.ApprovalID) <= 128
}

func validOperationError(value *agentv1.OperationError) bool {
	return strings.TrimSpace(value.Code) != "" && len(value.Code) <= 64 && strings.TrimSpace(value.Message) != "" && len(value.Message) <= 500
}

func validState(state agentv1.State) bool {
	switch state {
	case agentv1.StatePending, agentv1.StateApproved, agentv1.StateExecuting, agentv1.StateSucceeded,
		agentv1.StateFailed, agentv1.StateDenied, agentv1.StateExpired, agentv1.StateCanceled:
		return true
	default:
		return false
	}
}

func clone(operation agentv1.Operation) agentv1.Operation {
	data, _ := json.Marshal(operation)
	var out agentv1.Operation
	_ = json.Unmarshal(data, &out)
	return out
}

func randomID() (string, error) {
	data := make([]byte, 18)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return "op_" + base64.RawURLEncoding.EncodeToString(data), nil
}
