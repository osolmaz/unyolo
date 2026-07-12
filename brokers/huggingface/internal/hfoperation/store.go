// Package hfoperation stores durable hf-broker Agent Operations V1 records.
package hfoperation

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/store"
)

const (
	fileVersion       = 1
	maxJSONBytes      = 4096
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
}

type fileData struct {
	Version    int                 `json:"version"`
	Operations []agentv1.Operation `json:"operations"`
}

type Store struct {
	path   string
	now    func() time.Time
	newID  func() (string, error)
	mu     sync.Mutex
	signal chan struct{}
}

func New(path string) *Store {
	return newStore(path, time.Now, randomID)
}

func newStore(path string, now func() time.Time, newID func() (string, error)) *Store {
	return &Store{path: path, now: now, newID: newID, signal: make(chan struct{})}
}

func (s *Store) Submit(input Submit) (agentv1.Operation, bool, error) {
	normalized, err := normalizeSubmit(input)
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	now := s.now().UTC()
	data.Operations = retainedOperations(data.Operations, now.Add(-terminalRetention))
	for _, existing := range data.Operations {
		if existing.ClientID != normalized.ClientID || existing.IdempotencyKey != normalized.IdempotencyKey {
			continue
		}
		if !sameSubmission(existing, normalized) {
			return agentv1.Operation{}, false, ErrIdempotencyConflict
		}
		return clone(existing), false, nil
	}
	if len(data.Operations) >= maxOperations {
		return agentv1.Operation{}, false, ErrCapacity
	}
	id, err := s.newID()
	if err != nil {
		return agentv1.Operation{}, false, err
	}
	op := agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: id, Broker: normalized.Broker, ClientID: normalized.ClientID,
		IdempotencyKey: normalized.IdempotencyKey, Operation: normalized.Operation, Target: normalized.Target,
		Arguments: normalized.Arguments, Reason: normalized.Reason, State: agentv1.StatePending, Revision: 1,
		CreatedAt: now, UpdatedAt: now, Presentation: normalized.Presentation,
	}
	data.Operations = append(data.Operations, op)
	if err := s.write(data); err != nil {
		return agentv1.Operation{}, false, err
	}
	s.notify()
	return clone(op), true, nil
}

func retainedOperations(operations []agentv1.Operation, cutoff time.Time) []agentv1.Operation {
	retained := operations[:0]
	for _, operation := range operations {
		if operation.State.Terminal() && operation.UpdatedAt.Before(cutoff) {
			continue
		}
		retained = append(retained, operation)
	}
	return retained
}

func (s *Store) Get(clientID, id string) (agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(clientID, id)
}

func (s *Store) getLocked(clientID, id string) (agentv1.Operation, error) {
	data, err := s.read()
	if err != nil {
		return agentv1.Operation{}, err
	}
	for _, operation := range data.Operations {
		if operation.ID == id && operation.ClientID == clientID {
			return clone(operation), nil
		}
	}
	return agentv1.Operation{}, ErrNotFound
}

func (s *Store) ListUnfinished() ([]agentv1.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.read()
	if err != nil {
		return nil, err
	}
	operations := make([]agentv1.Operation, 0, len(data.Operations))
	for _, operation := range data.Operations {
		if !operation.State.Terminal() {
			operations = append(operations, clone(operation))
		}
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
	result, err := normalizeObject(result)
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
	if state != agentv1.StateFailed && state != agentv1.StateDenied && state != agentv1.StateExpired && state != agentv1.StateCanceled {
		return agentv1.Operation{}, ErrInvalidTransition
	}
	if strings.TrimSpace(code) == "" || len(code) > 64 || strings.TrimSpace(message) == "" || len(message) > 500 {
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
	data, err := s.read()
	if err != nil {
		return agentv1.Operation{}, err
	}
	for index := range data.Operations {
		if data.Operations[index].ID != id {
			continue
		}
		operation := clone(data.Operations[index])
		if err := change(&operation); err != nil {
			return agentv1.Operation{}, err
		}
		operation.Revision++
		operation.UpdatedAt = s.now().UTC()
		if operation.State.Terminal() {
			terminal := operation.UpdatedAt
			operation.TerminalAt = &terminal
		}
		data.Operations[index] = operation
		if err := s.write(data); err != nil {
			return agentv1.Operation{}, err
		}
		s.notify()
		return clone(operation), nil
	}
	return agentv1.Operation{}, ErrNotFound
}

func (s *Store) notify() {
	close(s.signal)
	s.signal = make(chan struct{})
}

func (s *Store) read() (fileData, error) {
	data, err := os.ReadFile(s.path) // #nosec G304 -- broker state path is operator configured.
	if errors.Is(err, os.ErrNotExist) {
		return fileData{Version: fileVersion}, nil
	}
	if err != nil {
		return fileData{}, err
	}
	if err := strictjson.RejectDuplicateKeys(data); err != nil {
		return fileData{}, err
	}
	var value fileData
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return fileData{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fileData{}, errors.New("operation store has trailing data")
	}
	if value.Version != fileVersion {
		return fileData{}, errors.New("operation store version is unsupported")
	}
	for _, operation := range value.Operations {
		if err := validateStored(operation); err != nil {
			return fileData{}, fmt.Errorf("operation store contains an invalid record: %w", err)
		}
	}
	return value, nil
}

func (s *Store) write(data fileData) error {
	data.Version = fileVersion
	return store.WriteJSONAtomic(s.path, data, 0o600)
}

func normalizeSubmit(input Submit) (Submit, error) {
	input.Broker = strings.TrimSpace(input.Broker)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.Operation = strings.TrimSpace(input.Operation)
	input.Reason = strings.TrimSpace(input.Reason)
	input.Presentation.Title = strings.TrimSpace(input.Presentation.Title)
	input.Presentation.Summary = strings.TrimSpace(input.Presentation.Summary)
	if !validSubmitIdentity(input) {
		return Submit{}, errors.New("operation identity is invalid")
	}
	if !validSubmitPresentation(input) {
		return Submit{}, errors.New("operation presentation is invalid")
	}
	var err error
	input.Target, err = normalizeObject(input.Target)
	if err != nil {
		return Submit{}, fmt.Errorf("target: %w", err)
	}
	input.Arguments, err = normalizeObject(input.Arguments)
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
	return len(input.Reason) <= 512 && input.Presentation.Title != "" && len(input.Presentation.Title) <= 160 && len(input.Presentation.Summary) <= 500
}

func normalizeObject(value json.RawMessage) (json.RawMessage, error) {
	if len(value) == 0 || len(value) > maxJSONBytes {
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
		existing.Presentation == input.Presentation && equalJSON(existing.Target, input.Target) && equalJSON(existing.Arguments, input.Arguments)
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
		if _, err := normalizeObject(operation.Result); err != nil {
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
	if operation.State.Terminal() != (operation.TerminalAt != nil) {
		return errors.New("operation terminal timestamp is invalid")
	}
	if !validState(operation.State) || len(operation.ApprovalID) > 128 {
		return errors.New("operation state or approval is invalid")
	}
	if operation.Error != nil && !validOperationError(operation.Error) {
		return errors.New("operation error is invalid")
	}
	return nil
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
