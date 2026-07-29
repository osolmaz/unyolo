package grants

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// UseState identifies one operation-bound grant-use lifecycle state.
type UseState string

const (
	UseReserved  UseState = "reserved"
	UseCommitted UseState = "committed"
	UseReleased  UseState = "released"
	UseRetained  UseState = "retained"
)

var (
	ErrUseIdentityConflict = errors.New("grant use identity conflict")
	ErrUseSettled          = errors.New("grant use is already settled")
)

// GrantUse durably binds one grant budget reservation to one operation or
// native protocol request. It intentionally contains no provider payload.
type GrantUse struct {
	GrantID   string    `json:"grant_id"`
	RequestID string    `json:"request_id"`
	Operation string    `json:"operation"`
	State     UseState  `json:"state"`
	Revision  int64     `json:"revision"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	SettledAt time.Time `json:"settled_at,omitzero"`
}

// UseReservation returns the exact use record and its current grant aggregate.
type UseReservation struct {
	Grant    Grant
	Use      GrantUse
	Acquired bool
}

// NewUseRequestIdentity returns a distinct secret-free identity for one
// provider-native invocation. Explicitly idempotent operation APIs should use
// their stable operation ID instead.
func NewUseRequestIdentity() (string, error) {
	var value [18]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate grant use identity: %w", err)
	}
	return "native_" + base64.RawURLEncoding.EncodeToString(value[:]), nil
}

// DeriveUseRequestID returns a bounded stable reservation identity for one
// provider-native invocation and one grant.
func DeriveUseRequestID(grantID, requestIdentity string) (string, error) {
	if grantID == "" || requestIdentity == "" {
		return "", ErrUseIdentityConflict
	}
	digest := sha256.Sum256([]byte(grantID + "\x00" + requestIdentity))
	return "use_" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// ReserveUse atomically reserves one grant use for a stable request identity.
// Repeating the same grant, operation, and request identity returns the
// existing record without charging the budget again.
func (s *Store) ReserveUse(grantID, requestID, operation string) (UseReservation, error) {
	if !validUseIdentity(grantID, requestID, operation) {
		return UseReservation{}, ErrUseIdentityConflict
	}
	var created bool
	err := s.update(func(data *fileData) error {
		createdUse, updateErr := s.reserveUse(data, grantID, requestID, operation)
		created = createdUse
		return updateErr
	})
	if err != nil {
		return UseReservation{}, err
	}
	result, err := s.GetUse(grantID, requestID)
	result.Acquired = created
	return result, err
}

func (s *Store) reserveUse(data *fileData, grantID, requestID, operation string) (bool, error) {
	useIndex, existing, found := findUseIndex(data.Uses, requestID)
	if found {
		return s.reserveExistingUse(data, useIndex, existing, grantID, operation)
	}
	return s.reserveNewUse(data, grantID, requestID, operation)
}

func (s *Store) reserveExistingUse(data *fileData, useIndex int, use GrantUse, grantID, operation string) (bool, error) {
	if use.GrantID != grantID || use.Operation != operation {
		return false, ErrUseIdentityConflict
	}
	if use.State != UseReleased {
		return false, nil
	}
	grantIndex, grant, err := findGrant(data.Grants, grantID)
	if err != nil {
		return false, err
	}
	now := s.opts.Now().UTC()
	if !grantCanUse(grant, now) {
		return false, ErrNotActive
	}
	use.State = UseReserved
	use.Revision++
	use.UpdatedAt = now
	use.SettledAt = time.Time{}
	data.Uses[useIndex] = use
	grant.ReservationRevision++
	data.Grants[grantIndex] = aggregateGrantUses(grant, data.Uses)
	return true, nil
}

func (s *Store) reserveNewUse(data *fileData, grantID, requestID, operation string) (bool, error) {
	grantIndex, grant, err := findGrant(data.Grants, grantID)
	if err != nil {
		return false, err
	}
	if grant.Operation != operation {
		return false, ErrUseIdentityConflict
	}
	now := s.opts.Now().UTC()
	if !grantCanUse(grant, now) {
		return false, ErrNotActive
	}
	data.Uses = append(data.Uses, GrantUse{GrantID: grantID, RequestID: requestID, Operation: operation,
		State: UseReserved, Revision: 1, CreatedAt: now, UpdatedAt: now})
	grant.ReservationRevision++
	data.Grants[grantIndex] = aggregateGrantUses(grant, data.Uses)
	return true, nil
}

// CommitUse consumes the exact operation-bound reservation.
func (s *Store) CommitUse(grantID, requestID string) (UseReservation, error) {
	return s.settleUse(grantID, requestID, UseCommitted)
}

// ReleaseUse returns the exact undispatched reservation to the grant budget.
func (s *Store) ReleaseUse(grantID, requestID string) (UseReservation, error) {
	return s.settleUse(grantID, requestID, UseReleased)
}

// RetainUse preserves the exact reservation after an ambiguous provider result.
func (s *Store) RetainUse(grantID, requestID string) (UseReservation, error) {
	return s.settleUse(grantID, requestID, UseRetained)
}

func (s *Store) settleUse(grantID, requestID string, target UseState) (UseReservation, error) {
	if grantID == "" || requestID == "" || !validUseState(target) {
		return UseReservation{}, ErrUseIdentityConflict
	}
	err := s.update(func(data *fileData) error {
		return s.settleStoredUse(data, grantID, requestID, target)
	})
	if err != nil {
		return UseReservation{}, err
	}
	return s.GetUse(grantID, requestID)
}

func (s *Store) settleStoredUse(data *fileData, grantID, requestID string, target UseState) error {
	useIndex, use, found := findUseIndex(data.Uses, requestID)
	if !found || use.GrantID != grantID {
		return ErrUseIdentityConflict
	}
	grantIndex, grant, err := findGrant(data.Grants, grantID)
	if err != nil {
		return err
	}
	settle, err := useCanSettle(use, grant, target)
	if err != nil || !settle {
		return err
	}
	s.applyUseSettlement(data, useIndex, grantIndex, use, grant, target)
	return nil
}

func (s *Store) applyUseSettlement(data *fileData, useIndex, grantIndex int, use GrantUse, grant Grant, target UseState) {
	now := s.opts.Now().UTC()
	use.State = target
	use.Revision++
	use.UpdatedAt = now
	if useStateSettled(target) {
		use.SettledAt = now
	}
	data.Uses[useIndex] = use
	grant.ReservationRevision++
	if target == UseCommitted {
		grant.UseRevision++
	}
	data.Grants[grantIndex] = settleGrantUse(aggregateGrantUses(grant, data.Uses))
}

func useCanSettle(use GrantUse, grant Grant, target UseState) (bool, error) {
	if use.State == target {
		return false, nil
	}
	if useStateSettled(use.State) {
		return false, ErrUseSettled
	}
	if !reservationCanSettle(grant.Status) {
		return false, ErrNotActive
	}
	return true, nil
}

func useStateSettled(state UseState) bool { return state == UseCommitted || state == UseReleased }

func settleGrantUse(grant Grant) Grant {
	if grant.MaxUses.Exhausted(grant.UsedCount) && grant.Status != StatusRevoked {
		grant.Status = StatusConsumed
		grant.ExpiredFrom = ""
	}
	return grant
}

// GetUse returns one exact operation-bound use and its current grant aggregate.
func (s *Store) GetUse(grantID, requestID string) (UseReservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return UseReservation{}, err
	}
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	changed := s.prepareLifecycle(&data)
	changed = s.reconcileLifecycle(&data, before) || changed
	result, err := useReservationFromData(data, grantID, requestID)
	if err != nil {
		return UseReservation{}, err
	}
	if err := s.savePreparedLifecycle(data, eventSequence, changed); err != nil {
		return UseReservation{}, err
	}
	return result, nil
}

func useReservationFromData(data fileData, grantID, requestID string) (UseReservation, error) {
	_, grant, err := findGrant(data.Grants, grantID)
	if err != nil {
		return UseReservation{}, err
	}
	use, found := findUse(data.Uses, requestID)
	if !found || use.GrantID != grantID {
		return UseReservation{}, ErrUseIdentityConflict
	}
	return UseReservation{Grant: grant, Use: use}, nil
}

// ListUses returns the durable use records for one grant.
func (s *Store) ListUses(grantID string) ([]GrantUse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	if _, _, err := findGrant(data.Grants, grantID); err != nil {
		return nil, err
	}
	result := make([]GrantUse, 0)
	for _, use := range data.Uses {
		if use.GrantID == grantID {
			result = append(result, use)
		}
	}
	return result, nil
}

func validUseIdentity(grantID, requestID, operation string) bool {
	return grantID != "" && len(grantID) <= 128 && requestID != "" && len(requestID) <= 128 &&
		operation != "" && len(operation) <= 128 && !strings.ContainsAny(requestID, " \t\r\n")
}

func validUseState(state UseState) bool {
	switch state {
	case UseReserved, UseCommitted, UseReleased, UseRetained:
		return true
	default:
		return false
	}
}

func findUse(uses []GrantUse, requestID string) (GrantUse, bool) {
	_, use, found := findUseIndex(uses, requestID)
	return use, found
}

func findUseIndex(uses []GrantUse, requestID string) (int, GrantUse, bool) {
	for index, use := range uses {
		if use.RequestID == requestID {
			return index, use, true
		}
	}
	return -1, GrantUse{}, false
}

func validateLoadedUses(grants []Grant, uses []GrantUse) error {
	grantByID := make(map[string]Grant, len(grants))
	for _, grant := range grants {
		grantByID[grant.ID] = grant
	}
	if err := validateLoadedUseRecords(grantByID, uses); err != nil {
		return err
	}
	return validateLoadedUseAggregates(grants, uses)
}

func validateLoadedUseRecords(grantByID map[string]Grant, uses []GrantUse) error {
	seen := make(map[string]bool, len(uses))
	for _, use := range uses {
		grant, found := grantByID[use.GrantID]
		if !found || seen[use.RequestID] || !validLoadedUse(use, grant) {
			return ErrUnsupportedState
		}
		seen[use.RequestID] = true
	}
	return nil
}

func validLoadedUse(use GrantUse, grant Grant) bool {
	return validLoadedUseIdentity(use, grant) && validLoadedUseLifecycle(use)
}

func validLoadedUseIdentity(use GrantUse, grant Grant) bool {
	return validUseIdentity(use.GrantID, use.RequestID, use.Operation) && grant.Operation == use.Operation
}

func validLoadedUseLifecycle(use GrantUse) bool {
	if !validUseState(use.State) || use.Revision < 1 {
		return false
	}
	return !use.CreatedAt.IsZero() && !use.UpdatedAt.Before(use.CreatedAt) && validUseSettlementTime(use)
}

func validateLoadedUseAggregates(grants []Grant, uses []GrantUse) error {
	for _, grant := range grants {
		aggregated := aggregateGrantUses(grant, uses)
		want := grantUseAggregate{UsedCount: aggregated.UsedCount, ReservedCount: aggregated.ReservedCount,
			ReservationRetained: aggregated.ReservationRetained, UsedAt: aggregated.UsedAt, ReservedAt: aggregated.ReservedAt,
			UseRevision: aggregated.UsedCount, ReservationRevision: useRevisionTotal(grant.ID, uses)}
		if grantUseAggregateFromGrant(grant) != want {
			return ErrUnsupportedState
		}
	}
	return nil
}

type grantUseAggregate struct {
	UsedCount, ReservedCount, UseRevision, ReservationRevision int
	ReservationRetained                                        bool
	UsedAt, ReservedAt                                         time.Time
}

func grantUseAggregateFromGrant(grant Grant) grantUseAggregate {
	return grantUseAggregate{UsedCount: grant.UsedCount, ReservedCount: grant.ReservedCount,
		UseRevision: grant.UseRevision, ReservationRevision: grant.ReservationRevision,
		ReservationRetained: grant.ReservationRetained, UsedAt: grant.UsedAt, ReservedAt: grant.ReservedAt}
}

func validUseSettlementTime(use GrantUse) bool {
	terminal := use.State == UseCommitted || use.State == UseReleased
	return terminal == !use.SettledAt.IsZero() && (use.SettledAt.IsZero() || !use.SettledAt.Before(use.UpdatedAt))
}

func useRevisionTotal(grantID string, uses []GrantUse) int {
	total := 0
	for _, use := range uses {
		if use.GrantID == grantID {
			total += int(use.Revision)
		}
	}
	return total
}

func aggregateGrantUses(grant Grant, uses []GrantUse) Grant {
	grant.UsedCount = 0
	grant.ReservedCount = 0
	grant.ReservedAt = time.Time{}
	grant.ReservationRetained = false
	grant.UsedAt = time.Time{}
	for _, use := range uses {
		if use.GrantID == grant.ID {
			grant = aggregateGrantUse(grant, use)
		}
	}
	return grant
}

func aggregateGrantUse(grant Grant, use GrantUse) Grant {
	switch use.State {
	case UseCommitted:
		grant.UsedCount++
		if grant.UsedAt.Before(use.SettledAt) {
			grant.UsedAt = use.SettledAt
		}
	case UseReserved, UseRetained:
		grant.ReservedCount++
		if grant.ReservedAt.IsZero() || use.UpdatedAt.Before(grant.ReservedAt) {
			grant.ReservedAt = use.UpdatedAt
		}
		if use.State == UseRetained {
			grant.ReservationRetained = true
		}
	case UseReleased:
	}
	return grant
}
