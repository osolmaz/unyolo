package grants

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
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

// DeriveUseRequestID returns a bounded stable reservation identity for a
// provider-native request and one grant. requestIdentity must already be a
// secret-free canonical identity, such as a method/path/body digest.
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
		if useIndex, existing, found := findUseIndex(data.Uses, requestID); found {
			if existing.GrantID != grantID || existing.Operation != operation {
				return ErrUseIdentityConflict
			}
			if existing.State != UseReleased {
				return nil
			}
			grantIndex, grant, findErr := findGrant(data.Grants, grantID)
			if findErr != nil {
				return findErr
			}
			now := s.opts.Now().UTC()
			if !grantCanUse(grant, now) {
				return ErrNotActive
			}
			existing.State = UseReserved
			existing.Revision++
			existing.UpdatedAt = now
			existing.SettledAt = time.Time{}
			data.Uses[useIndex] = existing
			grant.ReservationRevision++
			data.Grants[grantIndex] = aggregateGrantUses(grant, data.Uses)
			created = true
			return nil
		}
		index, grant, err := findGrant(data.Grants, grantID)
		if err != nil {
			return err
		}
		if grant.Operation != operation {
			return ErrUseIdentityConflict
		}
		now := s.opts.Now().UTC()
		if !grantCanUse(grant, now) {
			return ErrNotActive
		}
		data.Uses = append(data.Uses, GrantUse{GrantID: grantID, RequestID: requestID, Operation: operation,
			State: UseReserved, Revision: 1, CreatedAt: now, UpdatedAt: now})
		grant.ReservationRevision++
		data.Grants[index] = aggregateGrantUses(grant, data.Uses)
		created = true
		return nil
	})
	if err != nil {
		return UseReservation{}, err
	}
	result, err := s.GetUse(grantID, requestID)
	result.Acquired = created
	return result, err
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
		useIndex, use, found := findUseIndex(data.Uses, requestID)
		if !found || use.GrantID != grantID {
			return ErrUseIdentityConflict
		}
		grantIndex, grant, err := findGrant(data.Grants, grantID)
		if err != nil {
			return err
		}
		if use.State == target {
			return nil
		}
		if use.State == UseCommitted || use.State == UseReleased {
			return ErrUseSettled
		}
		if !reservationCanSettle(grant.Status) {
			return ErrNotActive
		}
		now := s.opts.Now().UTC()
		use.State = target
		use.Revision++
		use.UpdatedAt = now
		if target == UseCommitted || target == UseReleased {
			use.SettledAt = now
		}
		data.Uses[useIndex] = use
		grant.ReservationRevision++
		if target == UseCommitted {
			grant.UseRevision++
		}
		grant = aggregateGrantUses(grant, data.Uses)
		if grant.MaxUses.Exhausted(grant.UsedCount) && grant.Status != StatusRevoked {
			grant.Status = StatusConsumed
			grant.ExpiredFrom = ""
		}
		data.Grants[grantIndex] = grant
		return nil
	})
	if err != nil {
		return UseReservation{}, err
	}
	return s.GetUse(grantID, requestID)
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
	_, grant, err := findGrant(data.Grants, grantID)
	if err != nil {
		return UseReservation{}, err
	}
	use, found := findUse(data.Uses, requestID)
	if !found || use.GrantID != grantID {
		return UseReservation{}, ErrUseIdentityConflict
	}
	if changed {
		if err := s.save(data); err != nil {
			return UseReservation{}, err
		}
		s.signalNewEvents(eventSequence, data.NextEvent)
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
	seen := make(map[string]bool, len(uses))
	for _, use := range uses {
		grant, found := grantByID[use.GrantID]
		if !found || seen[use.RequestID] || !validUseIdentity(use.GrantID, use.RequestID, use.Operation) ||
			grant.Operation != use.Operation || !validUseState(use.State) || use.Revision < 1 || use.CreatedAt.IsZero() ||
			use.UpdatedAt.Before(use.CreatedAt) || !validUseSettlementTime(use) {
			return ErrUnsupportedState
		}
		seen[use.RequestID] = true
	}
	for _, grant := range grants {
		aggregated := aggregateGrantUses(grant, uses)
		if grant.UsedCount != aggregated.UsedCount || grant.ReservedCount != aggregated.ReservedCount ||
			grant.ReservationRetained != aggregated.ReservationRetained || !grant.UsedAt.Equal(aggregated.UsedAt) ||
			!grant.ReservedAt.Equal(aggregated.ReservedAt) || grant.UseRevision != aggregated.UsedCount ||
			grant.ReservationRevision != useRevisionTotal(grant.ID, uses) {
			return ErrUnsupportedState
		}
	}
	return nil
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
		if use.GrantID != grant.ID {
			continue
		}
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
			grant.ReservationRetained = grant.ReservationRetained || use.State == UseRetained
		}
	}
	return grant
}
