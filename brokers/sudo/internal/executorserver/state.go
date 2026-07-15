package executorserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/store"
)

const (
	executionClaimed   = "claimed"
	executionStarted   = "started"
	executionComplete  = "complete"
	maxStateBytes      = 16 << 20
	maxStateRecords    = 100_000
	completedRetention = 30 * 24 * time.Hour
)

var errExecutionConflict = errors.New("execution id already binds another plan")

type executionRecord struct {
	ID            string                    `json:"id"`
	PlanDigest    string                    `json:"plan_digest"`
	GrantID       string                    `json:"grant_id"`
	ReservationID string                    `json:"reservation_id"`
	Status        string                    `json:"status"`
	ClaimedAt     time.Time                 `json:"claimed_at"`
	StartedAt     time.Time                 `json:"started_at,omitempty"`
	CompletedAt   time.Time                 `json:"completed_at,omitempty"`
	Outcome       *executorprotocol.Outcome `json:"outcome,omitempty"`
}

type executionFile struct {
	Version    int               `json:"version"`
	Executions []executionRecord `json:"executions"`
}

type executionState struct {
	path string
	now  func() time.Time
	mu   sync.Mutex
}

func newExecutionState(path string, now func() time.Time) (*executionState, error) {
	if path == "" {
		return nil, errors.New("helper execution state path is required")
	}
	if now == nil {
		now = time.Now
	}
	return &executionState{path: path, now: now}, nil
}

func (s *executionState) lookup(id string, digest string, grantID string, reservationID string) (executionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return executionRecord{}, false, err
	}
	for _, record := range data.Executions {
		if record.ID != id {
			continue
		}
		if !sameExecutionBinding(record, digest, grantID, reservationID) {
			return executionRecord{}, false, errExecutionConflict
		}
		return record, true, nil
	}
	return executionRecord{}, false, nil
}

func (s *executionState) claim(id string, digest string, grantID string, reservationID string) (executionRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return executionRecord{}, false, err
	}
	data.Executions = pruneCompleted(data.Executions, s.now().UTC().Add(-completedRetention))
	for _, record := range data.Executions {
		if record.ID != id {
			continue
		}
		if !sameExecutionBinding(record, digest, grantID, reservationID) {
			return executionRecord{}, false, errExecutionConflict
		}
		return record, false, nil
	}
	if len(data.Executions) >= maxStateRecords {
		return executionRecord{}, false, errors.New("helper execution state capacity is exhausted")
	}
	record := executionRecord{ID: id, PlanDigest: digest, GrantID: grantID, ReservationID: reservationID, Status: executionClaimed, ClaimedAt: s.now().UTC()}
	data.Executions = append(data.Executions, record)
	if err := s.save(data); err != nil {
		return executionRecord{}, false, err
	}
	return record, true, nil
}

func sameExecutionBinding(record executionRecord, digest string, grantID string, reservationID string) bool {
	return record.PlanDigest == digest && record.GrantID == grantID && record.ReservationID == reservationID
}

func (s *executionState) markStarted(id string) error {
	return s.update(id, func(record *executionRecord) error {
		if record.Status != executionClaimed {
			return errors.New("execution is not claimable")
		}
		record.Status = executionStarted
		record.StartedAt = s.now().UTC()
		return nil
	})
}

func (s *executionState) complete(id string, outcome executorprotocol.Outcome) error {
	return s.update(id, func(record *executionRecord) error {
		if record.Status != executionStarted {
			return errors.New("execution cannot be completed")
		}
		record.Status = executionComplete
		record.CompletedAt = s.now().UTC()
		record.Outcome = &outcome
		return nil
	})
}

func (s *executionState) update(id string, mutate func(*executionRecord) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return err
	}
	for index := range data.Executions {
		if data.Executions[index].ID == id {
			if err := mutate(&data.Executions[index]); err != nil {
				return err
			}
			return s.save(data)
		}
	}
	return errors.New("execution does not exist")
}

func (s *executionState) load() (executionFile, error) {
	dataBytes, missing, err := readExecutionStateFile(s.path)
	if missing {
		return executionFile{Version: 1}, nil
	}
	if err != nil {
		return executionFile{}, err
	}
	data, err := decodeExecutionState(dataBytes)
	if err != nil {
		return executionFile{}, err
	}
	if err := validateExecutionFile(data); err != nil {
		return executionFile{}, err
	}
	return data, nil
}

func readExecutionStateFile(path string) ([]byte, bool, error) {
	dataBytes, err := os.ReadFile(path) // #nosec G304 -- root-owned helper state path.
	if errors.Is(err, os.ErrNotExist) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	if len(dataBytes) == 0 || len(dataBytes) > maxStateBytes {
		return nil, false, errors.New("helper execution state size is invalid")
	}
	return dataBytes, false, nil
}

func decodeExecutionState(dataBytes []byte) (executionFile, error) {
	if err := strictjson.RejectDuplicateKeys(dataBytes); err != nil {
		return executionFile{}, fmt.Errorf("decode helper execution state: %w", err)
	}
	var data executionFile
	decoder := json.NewDecoder(bytes.NewReader(dataBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return executionFile{}, fmt.Errorf("decode helper execution state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return executionFile{}, errors.New("decode helper execution state: trailing data")
	}
	if data.Version != 1 {
		return executionFile{}, errors.New("helper execution state version is unsupported")
	}
	return data, nil
}

func validateExecutionFile(data executionFile) error {
	if len(data.Executions) > maxStateRecords {
		return errors.New("helper execution state contains too many records")
	}
	seen := make(map[string]bool, len(data.Executions))
	for index, record := range data.Executions {
		if seen[record.ID] || validateExecutionRecord(record) != nil {
			return fmt.Errorf("helper execution state record %d is invalid", index)
		}
		seen[record.ID] = true
	}
	return nil
}

func (s *executionState) save(data executionFile) error {
	data.Version = 1
	if len(data.Executions) > maxStateRecords {
		return errors.New("helper execution state contains too many records")
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > maxStateBytes {
		return errors.New("helper execution state exceeds its size limit")
	}
	return store.WriteFileAtomic(s.path, append(encoded, '\n'), 0o600)
}

func validateExecutionRecord(record executionRecord) error {
	if err := validateExecutionBinding(record); err != nil {
		return err
	}
	switch record.Status {
	case executionClaimed:
		return validateClaimedExecution(record)
	case executionStarted:
		return validateStartedExecution(record)
	case executionComplete:
		return validateCompletedExecution(record)
	default:
		return errors.New("execution status is invalid")
	}
}

func validateExecutionBinding(record executionRecord) error {
	if !boundedStateID(record.ID) || !plandigest.Valid(record.PlanDigest) ||
		!boundedStateID(record.GrantID) || !boundedStateID(record.ReservationID) || record.ClaimedAt.IsZero() {
		return errors.New("execution binding is invalid")
	}
	return nil
}

func validateClaimedExecution(record executionRecord) error {
	if !record.StartedAt.IsZero() || !record.CompletedAt.IsZero() || record.Outcome != nil {
		return errors.New("claimed execution fields are invalid")
	}
	return nil
}

func validateStartedExecution(record executionRecord) error {
	if record.StartedAt.Before(record.ClaimedAt) || record.StartedAt.IsZero() ||
		!record.CompletedAt.IsZero() || record.Outcome != nil {
		return errors.New("started execution fields are invalid")
	}
	return nil
}

func validateCompletedExecution(record executionRecord) error {
	if invalidCompletedExecutionTimes(record) || record.Outcome == nil {
		return errors.New("completed execution fields are invalid")
	}
	return executorprotocol.WriteResponse(io.Discard, executorprotocol.NewCompleted(record.ID, *record.Outcome))
}

func invalidCompletedExecutionTimes(record executionRecord) bool {
	return record.CompletedAt.Before(record.ClaimedAt) || record.CompletedAt.IsZero() ||
		record.StartedAt.IsZero() || record.StartedAt.Before(record.ClaimedAt) || record.CompletedAt.Before(record.StartedAt)
}

func boundedStateID(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func pruneCompleted(records []executionRecord, cutoff time.Time) []executionRecord {
	return slices.DeleteFunc(records, func(record executionRecord) bool {
		return record.Status == executionComplete && record.CompletedAt.Before(cutoff)
	})
}
