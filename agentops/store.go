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
	defaultListLimit  = 20
	maxListLimit      = 50
	// TerminalRetention is the period during which completed operation keys
	// remain replayable.
	TerminalRetention = 30 * 24 * time.Hour
)

var (
	ErrNotFound            = errors.New("operation not found")
	ErrIdempotencyConflict = errors.New("operation idempotency conflict")
	ErrInvalidTransition   = errors.New("invalid operation state transition")
	ErrNotCancelable       = errors.New("operation is not cancelable")
	ErrCapacity            = errors.New("operation store capacity reached")
	errNoOperationChange   = errors.New("operation does not need an update")
)

type Submit struct {
	ID             string
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

// NewID allocates an operation identifier for callers that bind an approval
// and immutable plan before inserting the operation row.
func (s *Store) NewID() (string, error) {
	if s == nil || s.newID == nil {
		return "", errors.New("operation ID generator is unavailable")
	}
	return s.newID()
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
	return s.submit(input, nil, agentv1.StatePending)
}

// SubmitWithPlan atomically persists an immutable execution plan and its
// operation. Replays must provide the same plan digest.
func (s *Store) SubmitWithPlan(input Submit, plan state.PlanRecord) (agentv1.Operation, bool, error) {
	return s.submitWithPlan(input, plan, agentv1.StatePending)
}

// SubmitApprovedWithPlan atomically persists a direct operation in its approved
// state so restart recovery never has to infer whether approval was required.
func (s *Store) SubmitApprovedWithPlan(input Submit, plan state.PlanRecord) (agentv1.Operation, bool, error) {
	return s.submitWithPlan(input, plan, agentv1.StateApproved)
}

func (s *Store) submitWithPlan(input Submit, plan state.PlanRecord, initialState agentv1.State) (agentv1.Operation, bool, error) {
	input.PlanDigest = plan.Digest
	return s.submit(input, &plan, initialState)
}

func (s *Store) submit(input Submit, plan *state.PlanRecord, initialState agentv1.State) (agentv1.Operation, bool, error) {
	normalized, err := normalizeSubmit(input)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.submitLocked(normalized, plan, initialState)
}

func (s *Store) submitLocked(input Submit, plan *state.PlanRecord, initialState agentv1.State) (agentv1.Operation, bool, error) {
	ctx := context.Background()
	now := s.now().UTC()
	if _, err := s.db.DeleteTerminalOperationsBefore(ctx, now.Add(-TerminalRetention)); err != nil {
		return agentv1.Operation{}, false, err
	}
	if existing, found, err := s.findSubmission(ctx, input); err != nil || found {
		return existing, false, err
	}
	return s.createOperation(ctx, input, now, plan, initialState)
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

func (s *Store) createOperation(ctx context.Context, input Submit, now time.Time, plan *state.PlanRecord, initialState agentv1.State) (agentv1.Operation, bool, error) {
	count, err := s.db.CountOperations(ctx)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	if count >= maxOperations {
		return agentv1.Operation{}, false, ErrCapacity
	}
	id := input.ID
	if id == "" {
		var err error
		id, err = s.NewID()
		if err != nil {
			return agentv1.Operation{}, false, err
		}
	}
	op := agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: id, Broker: input.Broker, ClientID: input.ClientID,
		IdempotencyKey: input.IdempotencyKey, Operation: input.Operation, Target: input.Target,
		Arguments: input.Arguments, Reason: input.Reason, State: initialState, Revision: 1,
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

// GetByIdempotency returns an existing submission for provider lifecycle
// services that must avoid re-resolving mutable upstream state on replay.
func (s *Store) GetByIdempotency(clientID, key string) (agentv1.Operation, error) {
	clientID, key = strings.TrimSpace(clientID), strings.TrimSpace(key)
	if clientID == "" || key == "" {
		return agentv1.Operation{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.db.OperationByIdempotency(context.Background(), clientID, key)
	return storedOperation(record, err)
}

// List returns one bounded, deterministic page owned by clientID.
func (s *Store) List(clientID string, options agentv1.ListOptions) (agentv1.OperationPage, error) {
	clientID, options, err := normalizeListOptions(clientID, options)
	if err != nil {
		return agentv1.OperationPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.db.OperationsForClient(context.Background(), state.OperationListOptions{
		ClientID: clientID, IdempotencyKey: options.IdempotencyKey, State: string(options.State),
		Cursor: options.Cursor, Limit: options.Limit + 1,
	})
	if err != nil {
		return agentv1.OperationPage{}, mapStateError(err)
	}
	return operationPage(records, options.Limit)
}

func normalizeListOptions(clientID string, options agentv1.ListOptions) (string, agentv1.ListOptions, error) {
	clientID = strings.TrimSpace(clientID)
	options.IdempotencyKey = strings.TrimSpace(options.IdempotencyKey)
	options.Cursor = strings.TrimSpace(options.Cursor)
	if options.Limit == 0 {
		options.Limit = defaultListLimit
	}
	if clientID == "" || len(options.IdempotencyKey) > 128 || len(options.Cursor) > 128 {
		return "", agentv1.ListOptions{}, errors.New("operation list options are invalid")
	}
	if options.Limit < 1 || options.Limit > maxListLimit || !validListState(options.State) {
		return "", agentv1.ListOptions{}, errors.New("operation list options are invalid")
	}
	return clientID, options, nil
}

func operationPage(records []state.OperationRecord, limit int) (agentv1.OperationPage, error) {
	page := agentv1.OperationPage{APIVersion: agentv1.APIVersion, Operations: make([]agentv1.OperationSummary, 0, min(len(records), limit))}
	for _, record := range records[:min(len(records), limit)] {
		operation, convertErr := operationFromRecord(record)
		if convertErr != nil {
			return agentv1.OperationPage{}, convertErr
		}
		page.Operations = append(page.Operations, operationSummary(operation))
	}
	if len(records) > limit {
		cursor := page.Operations[len(page.Operations)-1].ID
		page.NextCursor = &cursor
	}
	return page, nil
}

func operationSummary(operation agentv1.Operation) agentv1.OperationSummary {
	return agentv1.OperationSummary{
		APIVersion: operation.APIVersion, ID: operation.ID, Broker: operation.Broker, ClientID: operation.ClientID,
		IdempotencyKey: operation.IdempotencyKey, Operation: operation.Operation, State: operation.State,
		Revision: operation.Revision, CreatedAt: operation.CreatedAt, UpdatedAt: operation.UpdatedAt,
		TerminalAt: operation.TerminalAt, Presentation: operation.Presentation,
	}
}

func validListState(value agentv1.State) bool {
	if value == "" {
		return true
	}
	switch value {
	case agentv1.StatePending, agentv1.StateApproved, agentv1.StateExecuting, agentv1.StateSucceeded,
		agentv1.StateFailed, agentv1.StateDenied, agentv1.StateExpired, agentv1.StateCanceled:
		return true
	default:
		return false
	}
}

// Cancel atomically cancels a requester-owned pending or approved operation.
// Terminal operations are returned unchanged; executing work is not cancelable.
func (s *Store) Cancel(clientID, id string) (agentv1.Operation, error) {
	return s.update(id, func(operation *agentv1.Operation) error {
		if operation.ClientID != clientID {
			return ErrNotFound
		}
		if operation.State.Terminal() {
			return errNoOperationChange
		}
		if operation.State != agentv1.StatePending && operation.State != agentv1.StateApproved {
			return ErrNotCancelable
		}
		operation.State = agentv1.StateCanceled
		operation.Error = &agentv1.OperationError{Code: "operation_canceled", Message: "Request was canceled"}
		return nil
	})
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

// BindPlan atomically stores the immutable plan and binds a pending operation
// to either an approval request or direct execution.
func (s *Store) BindPlan(id string, plan state.PlanRecord, approvalID string, direct bool) (agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	operation, err := storedOperation(s.db.OperationByID(context.Background(), id))
	if err != nil {
		return agentv1.Operation{}, err
	}
	approvalID = strings.TrimSpace(approvalID)
	if !validPlanBinding(operation, plan, approvalID, direct) {
		return agentv1.Operation{}, ErrInvalidTransition
	}
	expectedRevision := operation.Revision
	operation.PlanDigest = plan.Digest
	operation.ApprovalID = approvalID
	if direct {
		operation.State = agentv1.StateApproved
	}
	prepareOperationUpdate(&operation, s.now())
	updated, err := s.db.UpdateOperationWithPlan(context.Background(), operationRecord(operation), expectedRevision, plan)
	if err != nil {
		return agentv1.Operation{}, err
	}
	if !updated {
		return agentv1.Operation{}, ErrInvalidTransition
	}
	s.notify()
	return clone(operation), nil
}

func validPlanBinding(operation agentv1.Operation, plan state.PlanRecord, approvalID string, direct bool) bool {
	return operation.State == agentv1.StatePending && operation.PlanDigest == "" && direct != (approvalID != "") &&
		plandigest.Valid(plan.Digest)
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
	changed, err := applyOperationChange(&operation, change)
	if err != nil {
		return agentv1.Operation{}, err
	}
	if !changed {
		return clone(operation), nil
	}
	expectedRevision := operation.Revision
	prepareOperationUpdate(&operation, s.now())
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

func applyOperationChange(operation *agentv1.Operation, change func(*agentv1.Operation) error) (bool, error) {
	err := change(operation)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, errNoOperationChange) {
		return false, nil
	}
	return false, err
}

func prepareOperationUpdate(operation *agentv1.Operation, now time.Time) {
	operation.Revision++
	operation.UpdatedAt = now.UTC()
	if operation.State.Terminal() {
		terminal := operation.UpdatedAt
		operation.TerminalAt = &terminal
	}
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
	input.ID = strings.TrimSpace(input.ID)
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
	return (input.ID == "" || validOperationID(input.ID)) &&
		validRequiredValue(input.Broker, 64) &&
		validRequiredValue(input.ClientID, 128) &&
		validRequiredValue(input.IdempotencyKey, 128) &&
		validRequiredValue(input.Operation, 128)
}

func validRequiredValue(value string, maximum int) bool {
	return value != "" && len(value) <= maximum
}

func validOperationID(value string) bool {
	return strings.HasPrefix(value, "op_") && len(value) >= 8 && len(value) <= 128 && !strings.ContainsAny(value, " \t\r\n")
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
