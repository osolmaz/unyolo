package grants

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	defaultMaxEvents = 10_000
	maxEventPageSize = 100
)

// EventKind identifies one durable grant lifecycle transition.
type EventKind string

const (
	EventRequestCreated     EventKind = "request.created"
	EventRequestApproved    EventKind = "request.approved"
	EventRequestDenied      EventKind = "request.denied"
	EventRequestCanceled    EventKind = "request.canceled"
	EventRequestExpired     EventKind = "request.expired"
	EventGrantRevoked       EventKind = "grant.revoked"
	EventGrantReserved      EventKind = "grant.reserved"
	EventGrantConsumed      EventKind = "grant.consumed"
	EventGrantReleased      EventKind = "grant.released"
	EventExecutionSucceeded EventKind = "execution.succeeded"
	EventExecutionFailed    EventKind = "execution.failed"
	EventExecutionAmbiguous EventKind = "execution.ambiguous"
)

var (
	ErrInvalidCursor = errors.New("invalid event cursor")
	ErrCursorExpired = errors.New("event cursor is no longer retained")
)

// Event is the safe durable lifecycle notification returned to consumers.
type Event struct {
	Cursor        string    `json:"cursor"`
	Kind          EventKind `json:"kind"`
	GrantID       string    `json:"grant_id"`
	Status        Status    `json:"status"`
	UsedCount     int       `json:"used_count"`
	ReservedCount int       `json:"reserved_count"`
	Revision      int64     `json:"revision"`
	Time          time.Time `json:"time"`
}

// EventPage is one bounded event-cursor result.
type EventPage struct {
	Events     []Event `json:"events"`
	NextCursor string  `json:"next_cursor,omitempty"`
	HasMore    bool    `json:"has_more"`
}

type lifecycleEventRecord struct {
	Sequence      uint64    `json:"sequence"`
	Kind          EventKind `json:"kind"`
	GrantID       string    `json:"grant_id"`
	Status        Status    `json:"status"`
	UsedCount     int       `json:"used_count"`
	ReservedCount int       `json:"reserved_count"`
	Revision      int64     `json:"revision"`
	Time          time.Time `json:"time"`
}

func grantSnapshots(grants []Grant) map[string]Grant {
	out := make(map[string]Grant, len(grants))
	for _, grant := range grants {
		out[grant.ID] = grant
	}
	return out
}

func (s *Store) reconcileLifecycle(data *fileData, before map[string]Grant) bool {
	changed := false
	for index := range data.Grants {
		grant := data.Grants[index]
		previous, exists := before[grant.ID]
		kinds := lifecycleKinds(previous, grant, exists)
		if len(kinds) == 0 {
			continue
		}
		if exists {
			grant.Revision = previous.Revision + 1
		} else {
			grant.Revision = 1
		}
		data.Grants[index] = grant
		for _, kind := range kinds {
			s.appendLifecycleEvent(data, kind, grant)
		}
		changed = true
	}
	return changed
}

func lifecycleKinds(before Grant, after Grant, exists bool) []EventKind {
	if !exists {
		return []EventKind{EventRequestCreated}
	}
	kinds := statusEventKinds(before, after)
	switch {
	case after.UsedCount > before.UsedCount:
		kinds = append(kinds, EventGrantConsumed)
	case after.ReservedCount < before.ReservedCount:
		kinds = append(kinds, EventGrantReleased)
	}
	if after.ReservedCount > before.ReservedCount {
		kinds = append(kinds, EventGrantReserved)
	}
	if !before.ReservationRetained && after.ReservationRetained {
		kinds = append(kinds, EventExecutionAmbiguous)
	}
	return kinds
}

func statusEventKinds(before Grant, after Grant) []EventKind {
	if before.Status == after.Status {
		return nil
	}
	switch after.Status {
	case StatusActive:
		return []EventKind{EventRequestApproved}
	case StatusDenied:
		return []EventKind{EventRequestDenied}
	case StatusCanceled:
		return []EventKind{EventRequestCanceled}
	case StatusExpired:
		return []EventKind{EventRequestExpired}
	case StatusRevoked:
		return []EventKind{EventGrantRevoked}
	case StatusPending, StatusConsumed:
		return nil
	default:
		return nil
	}
}

func (s *Store) appendLifecycleEvent(data *fileData, kind EventKind, grant Grant) {
	if data.NextEvent == 0 {
		data.NextEvent = 1
	}
	record := lifecycleEventRecord{
		Sequence: data.NextEvent, Kind: kind, GrantID: grant.ID, Status: grant.Status,
		UsedCount: grant.UsedCount, ReservedCount: grant.ReservedCount,
		Revision: grant.Revision, Time: s.opts.Now().UTC(),
	}
	data.NextEvent++
	data.Events = append(data.Events, record)
	if excess := len(data.Events) - s.opts.MaxEvents; excess > 0 {
		data.Events = append([]lifecycleEventRecord(nil), data.Events[excess:]...)
	}
}

func normalizeLoadedEvents(data *fileData) error {
	var previous uint64
	for _, event := range data.Events {
		if event.Sequence == 0 || event.Sequence <= previous {
			return errors.New("grant lifecycle events are not strictly ordered")
		}
		previous = event.Sequence
	}
	if data.NextEvent == 0 {
		data.NextEvent = previous + 1
	}
	if data.NextEvent <= previous {
		return errors.New("grant lifecycle next event is invalid")
	}
	return nil
}

// EventsAfter returns durable events strictly after cursor.
func (s *Store) EventsAfter(cursor string, limit int) (EventPage, error) {
	sequence, limit, err := normalizeEventRequest(cursor, limit)
	if err != nil {
		return EventPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return EventPage{}, err
	}
	sequence, err = eventStartingSequence(data.Events, cursor, sequence)
	if err != nil {
		return EventPage{}, err
	}
	return eventPageAfter(data.Events, sequence, limit), nil
}

func normalizeEventRequest(cursor string, limit int) (uint64, int, error) {
	sequence, err := decodeEventCursor(cursor)
	if err != nil {
		return 0, 0, err
	}
	normalizedLimit, err := normalizeEventLimit(limit)
	return sequence, normalizedLimit, err
}

func eventStartingSequence(events []lifecycleEventRecord, cursor string, sequence uint64) (uint64, error) {
	if len(events) == 0 {
		return sequence, nil
	}
	if cursor == "" {
		return events[0].Sequence - 1, nil
	}
	if sequence < events[0].Sequence-1 {
		return 0, ErrCursorExpired
	}
	return sequence, nil
}

func eventPageAfter(events []lifecycleEventRecord, sequence uint64, limit int) EventPage {
	records := make([]lifecycleEventRecord, 0, limit+1)
	for _, event := range events {
		if event.Sequence > sequence {
			records = append(records, event)
			if len(records) > limit {
				break
			}
		}
	}
	page := EventPage{HasMore: len(records) > limit}
	if page.HasMore {
		records = records[:limit]
	}
	page.Events = make([]Event, 0, len(records))
	for _, record := range records {
		page.Events = append(page.Events, publicEvent(record))
	}
	if len(records) > 0 {
		page.NextCursor = encodeEventCursor(records[len(records)-1].Sequence)
	}
	return page
}

// LatestEvent returns the newest retained lifecycle event for one grant.
func (s *Store) LatestEvent(id string) (Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Event{}, err
	}
	for index := len(data.Events) - 1; index >= 0; index-- {
		if data.Events[index].GrantID == id {
			return publicEvent(data.Events[index]), nil
		}
	}
	if _, _, err := findGrant(data.Grants, id); err != nil {
		return Event{}, err
	}
	return Event{}, ErrNotFound
}

// WaitForEvents blocks until an event exists after cursor or ctx is canceled.
func (s *Store) WaitForEvents(ctx context.Context, cursor string) (EventPage, error) {
	for {
		wait := s.eventWaitChannel()
		page, err := s.EventsAfter(cursor, 1)
		if err != nil || len(page.Events) > 0 {
			return page, err
		}
		select {
		case <-ctx.Done():
			return EventPage{}, ctx.Err()
		case <-wait:
		}
	}
}

// RecordExecution appends one safe provider execution outcome event.
func (s *Store) RecordExecution(id string, kind EventKind) (Event, error) {
	if kind != EventExecutionSucceeded && kind != EventExecutionFailed && kind != EventExecutionAmbiguous {
		return Event{}, errors.New("invalid execution event kind")
	}
	var out Event
	err := s.update(func(data *fileData) error {
		_, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		s.appendLifecycleEvent(data, kind, grant)
		out = publicEvent(data.Events[len(data.Events)-1])
		return nil
	})
	return out, err
}

func (s *Store) eventWaitChannel() <-chan struct{} {
	s.eventMu.Lock()
	defer s.eventMu.Unlock()
	return s.eventSignal
}

func (s *Store) signalNewEvents(before uint64, after uint64) {
	if before == after {
		return
	}
	s.eventMu.Lock()
	close(s.eventSignal)
	s.eventSignal = make(chan struct{})
	s.eventMu.Unlock()
}

func normalizeEventLimit(limit int) (int, error) {
	if limit == 0 {
		return 50, nil
	}
	if limit < 1 || limit > maxEventPageSize {
		return 0, fmt.Errorf("event limit must be between 1 and %d", maxEventPageSize)
	}
	return limit, nil
}

func encodeEventCursor(sequence uint64) string {
	var data [8]byte
	binary.BigEndian.PutUint64(data[:], sequence)
	return base64.RawURLEncoding.EncodeToString(data[:])
}

func decodeEventCursor(cursor string) (uint64, error) {
	if cursor == "" {
		return 0, nil
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil || len(data) != 8 {
		return 0, ErrInvalidCursor
	}
	return binary.BigEndian.Uint64(data), nil
}

func publicEvent(record lifecycleEventRecord) Event {
	return Event{
		Cursor: encodeEventCursor(record.Sequence), Kind: record.Kind, GrantID: record.GrantID,
		Status: record.Status, UsedCount: record.UsedCount, ReservedCount: record.ReservedCount,
		Revision: record.Revision, Time: record.Time,
	}
}
