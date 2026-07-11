package executorserver

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
	"github.com/osolmaz/brokerkit/store"
)

const (
	executionClaimed  = "claimed"
	executionStarted  = "started"
	executionComplete = "complete"
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
	for _, record := range data.Executions {
		if record.ID != id {
			continue
		}
		if !sameExecutionBinding(record, digest, grantID, reservationID) {
			return executionRecord{}, false, errExecutionConflict
		}
		return record, false, nil
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
		if record.Status != executionClaimed && record.Status != executionStarted {
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
	var data executionFile
	if err := store.ReadJSON(s.path, &data); err != nil {
		return executionFile{}, err
	}
	if data.Version == 0 {
		data.Version = 1
	}
	if data.Version != 1 {
		return executionFile{}, errors.New("helper execution state version is unsupported")
	}
	for index, record := range data.Executions {
		if record.ID == "" || record.PlanDigest == "" || record.GrantID == "" || record.ReservationID == "" ||
			(record.Status != executionClaimed && record.Status != executionStarted && record.Status != executionComplete) {
			return executionFile{}, fmt.Errorf("helper execution state record %d is invalid", index)
		}
	}
	return data, nil
}

func (s *executionState) save(data executionFile) error {
	data.Version = 1
	return store.WriteJSONAtomic(s.path, data, 0o600)
}
