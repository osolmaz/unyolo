package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/authorization/policy"
)

const maxGrantPageSize = 100

// StatusGroup selects a useful operator-inbox lifecycle group.
type StatusGroup string

const (
	StatusGroupPending StatusGroup = "pending"
	StatusGroupActive  StatusGroup = "active"
	StatusGroupHistory StatusGroup = "history"
	StatusGroupAll     StatusGroup = "all"
)

var (
	ErrInvalidGrantCursor = errors.New("invalid grant cursor")
	ErrInvalidQuery       = errors.New("invalid grant query")
)

// Query bounds and filters one operator-inbox listing.
type Query struct {
	StatusGroup StatusGroup
	Client      string
	Operation   string
	Target      *policy.Target
	Cursor      string
	Limit       int
}

// Page is one deterministic, bounded grant query result.
type Page struct {
	Grants      []Grant `json:"grants"`
	NextCursor  string  `json:"next_cursor,omitempty"`
	HasMore     bool    `json:"has_more"`
	EventCursor string  `json:"event_cursor,omitempty"`
}

type grantCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
	QueryHash string    `json:"query_hash"`
}

// QueryGrants returns grants newest first, with ID as a stable tiebreaker.
func (s *Store) QueryGrants(query Query) (Page, error) {
	query, cursor, err := normalizeGrantQuery(query)
	if err != nil {
		return Page{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Page{}, err
	}
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	changed := s.prepareLifecycle(&data)
	changed = s.reconcileLifecycle(&data, before) || changed
	if err := s.persistQueryLifecycle(data, eventSequence, changed); err != nil {
		return Page{}, err
	}
	page := buildGrantPage(data.Grants, query, cursor)
	if query.Cursor == "" && data.NextEvent > 1 {
		page.EventCursor = encodeEventCursor(data.NextEvent - 1)
	}
	return page, nil
}

func (s *Store) persistQueryLifecycle(data fileData, eventSequence uint64, changed bool) error {
	if !changed {
		return nil
	}
	if err := s.save(data); err != nil {
		return err
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return nil
}

func buildGrantPage(grants []Grant, query Query, cursor grantCursor) Page {
	filtered := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if grantMatchesQuery(grant, query) && grantBeforeCursor(grant, cursor) {
			filtered = append(filtered, grant)
		}
	}
	slices.SortFunc(filtered, compareGrantsNewestFirst)
	page := Page{HasMore: len(filtered) > query.Limit}
	if page.HasMore {
		filtered = filtered[:query.Limit]
	}
	page.Grants = filtered
	if len(filtered) > 0 {
		last := filtered[len(filtered)-1]
		page.NextCursor = encodeGrantCursor(grantCursor{CreatedAt: last.CreatedAt, ID: last.ID, QueryHash: queryFingerprint(query)})
	}
	return page
}

func normalizeGrantQuery(query Query) (Query, grantCursor, error) {
	query.StatusGroup = normalizedStatusGroup(query.StatusGroup)
	if !validStatusGroup(query.StatusGroup) {
		return Query{}, grantCursor{}, fmt.Errorf("%w: invalid status group %q", ErrInvalidQuery, query.StatusGroup)
	}
	query.Limit = normalizedGrantLimit(query.Limit)
	if query.Limit < 1 || query.Limit > maxGrantPageSize {
		return Query{}, grantCursor{}, fmt.Errorf("%w: grant limit must be between 1 and %d", ErrInvalidQuery, maxGrantPageSize)
	}
	var err error
	query.Target, err = normalizeOptionalQueryTarget(query.Target)
	if err != nil {
		return Query{}, grantCursor{}, err
	}
	cursor, err := decodeGrantCursor(query.Cursor)
	return query, cursor, validateGrantCursorQuery(cursor, query, err)
}

func normalizeOptionalQueryTarget(target *policy.Target) (*policy.Target, error) {
	if target == nil {
		return nil, nil
	}
	normalized, err := normalizeQueryTarget(*target)
	return &normalized, err
}

func validateGrantCursorQuery(cursor grantCursor, query Query, decodeErr error) error {
	if decodeErr != nil {
		return decodeErr
	}
	if cursor.ID != "" && cursor.QueryHash != queryFingerprint(query) {
		return ErrInvalidGrantCursor
	}
	return nil
}

func normalizedStatusGroup(group StatusGroup) StatusGroup {
	if group == "" {
		return StatusGroupAll
	}
	return group
}

func validStatusGroup(group StatusGroup) bool {
	return slices.Contains([]StatusGroup{StatusGroupPending, StatusGroupActive, StatusGroupHistory, StatusGroupAll}, group)
}

func normalizedGrantLimit(limit int) int {
	if limit == 0 {
		return 50
	}
	return limit
}

func queryFingerprint(query Query) string {
	query.Cursor = ""
	encoded, _ := json.Marshal(query)
	digest := sha256.Sum256(encoded)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func normalizeQueryTarget(target policy.Target) (policy.Target, error) {
	if strings.TrimSpace(target.Kind) == "" {
		return policy.Target{}, fmt.Errorf("%w: target kind is required", ErrInvalidQuery)
	}
	fields := make(map[string][]string, len(target.Fields))
	for key, values := range target.Fields {
		if strings.TrimSpace(key) == "" || len(values) == 0 {
			return policy.Target{}, fmt.Errorf("%w: target field is invalid", ErrInvalidQuery)
		}
		fields[key] = append([]string(nil), values...)
		for _, value := range fields[key] {
			if strings.TrimSpace(value) == "" {
				return policy.Target{}, fmt.Errorf("%w: target field is invalid", ErrInvalidQuery)
			}
		}
		slices.Sort(fields[key])
		fields[key] = slices.Compact(fields[key])
	}
	target.Fields = fields
	return target, nil
}

func grantMatchesQuery(grant Grant, query Query) bool {
	return grantMatchesIdentity(grant, query) && grantMatchesStatus(grant.Status, query.StatusGroup)
}

func grantMatchesIdentity(grant Grant, query Query) bool {
	return (query.Client == "" || grant.Client == query.Client) &&
		(query.Operation == "" || grant.Operation == query.Operation) &&
		(query.Target == nil || targetMatchesFilter(grant.Target, *query.Target))
}

func targetMatchesFilter(target policy.Target, filter policy.Target) bool {
	if target.Kind != filter.Kind {
		return false
	}
	for key, values := range filter.Fields {
		if !slices.Equal(target.Fields[key], values) {
			return false
		}
	}
	return true
}

func grantMatchesStatus(status Status, group StatusGroup) bool {
	switch group {
	case StatusGroupPending:
		return status == StatusPending
	case StatusGroupActive:
		return status == StatusActive
	case StatusGroupHistory:
		return status != StatusPending && status != StatusActive
	case StatusGroupAll:
		return true
	default:
		return false
	}
}

func compareGrantsNewestFirst(left Grant, right Grant) int {
	if left.CreatedAt.After(right.CreatedAt) {
		return -1
	}
	if left.CreatedAt.Before(right.CreatedAt) {
		return 1
	}
	if left.ID > right.ID {
		return -1
	}
	if left.ID < right.ID {
		return 1
	}
	return 0
}

func grantBeforeCursor(grant Grant, cursor grantCursor) bool {
	if cursor.ID == "" {
		return true
	}
	return grant.CreatedAt.Before(cursor.CreatedAt) ||
		(grant.CreatedAt.Equal(cursor.CreatedAt) && grant.ID < cursor.ID)
}

func encodeGrantCursor(cursor grantCursor) string {
	data, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeGrantCursor(cursor string) (grantCursor, error) {
	if cursor == "" {
		return grantCursor{}, nil
	}
	if len(cursor) > 512 {
		return grantCursor{}, ErrInvalidGrantCursor
	}
	data, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return grantCursor{}, ErrInvalidGrantCursor
	}
	return decodeGrantCursorData(data)
}

func decodeGrantCursorData(data []byte) (grantCursor, error) {
	var decoded grantCursor
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil || decoded.ID == "" || decoded.CreatedAt.IsZero() || decoded.QueryHash == "" {
		return grantCursor{}, ErrInvalidGrantCursor
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return grantCursor{}, ErrInvalidGrantCursor
	}
	return decoded, nil
}
