// Package grants stores pending and active operator grants.
//
// Grants are narrow, time-boxed exceptions to standing policy. The store
// persists grant metadata only; it never stores broker client secrets or
// upstream Hugging Face tokens.
package grants

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultPendingTimeout is how long an unapproved request remains pending.
	DefaultPendingTimeout = 10 * time.Minute
	// DefaultDuration is the grant duration used when a request omits minutes.
	DefaultDuration = 5 * time.Minute
	// MaxDuration is the hard cap for one approved grant.
	MaxDuration = time.Hour
	// DefaultMaxUses is the default use budget for an approved grant.
	DefaultMaxUses = 1
	// MaxUses is the hard cap for one grant's use budget.
	MaxUses = 25
	// DefaultReservationTimeout is how long a use reservation can remain
	// in-flight before restart recovery treats it as needing operator review.
	DefaultReservationTimeout = 5 * time.Minute
)

// Status is the lifecycle state of one grant request.
type Status string

// Grant lifecycle states.
const (
	StatusPending  Status = "pending"
	StatusActive   Status = "active"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
	StatusCanceled Status = "canceled"
	StatusConsumed Status = "consumed"
)

const (
	// NotifierStatusReserved means a grant notification should show that a
	// retained use reservation needs operator review.
	NotifierStatusReserved Status = "reserved"
	// NotifierStatusUsed means a grant notification should show that at least
	// one approved operation used the grant budget.
	NotifierStatusUsed Status = "used"
	// NotifierStatusUsedExpired means a partially used grant notification
	// should show that the access window is now closed.
	NotifierStatusUsedExpired Status = "used:expired"
)

var (
	// ErrNotFound means no grant with the requested id exists.
	ErrNotFound = errors.New("grant not found")
	// ErrInvalidDecisionToken means the callback token did not match the grant.
	ErrInvalidDecisionToken = errors.New("invalid grant decision token")
	// ErrNotPending means a decision arrived after the request was no longer pending.
	ErrNotPending = errors.New("grant is not pending")
	// ErrNotActive means a grant cannot be used because it is not active.
	ErrNotActive = errors.New("grant is not active")
)

// Options configures a Store.
type Options struct {
	PendingTimeout     time.Duration
	DefaultDuration    time.Duration
	MaxDuration        time.Duration
	ReservationTimeout time.Duration
	Now                func() time.Time
}

// Request is one requested grant.
type Request struct {
	Client            string
	ClientRequestID   string
	Operation         string
	Target            string
	Ref               string
	Reason            string
	RequestedDuration time.Duration
	MaxUses           int
}

// NotifierMessage identifies one operator notification that can be edited.
type NotifierMessage struct {
	Kind      string `json:"kind"`
	ChatID    int64  `json:"chat_id"`
	MessageID int    `json:"message_id"`
	Text      string `json:"text"`
}

// Grant is one persisted grant request or approval.
type Grant struct {
	ID                  string           `json:"id"`
	DecisionToken       string           `json:"decision_token"`
	Client              string           `json:"client"`
	ClientRequestID     string           `json:"client_request_id,omitempty"`
	Operation           string           `json:"operation"`
	Target              string           `json:"target"`
	Ref                 string           `json:"ref"`
	Reason              string           `json:"reason"`
	RequestedMinutes    int              `json:"requested_minutes"`
	MaxUses             int              `json:"max_uses"`
	UsedCount           int              `json:"used_count"`
	ReservedCount       int              `json:"reserved_count,omitempty"`
	ReservationRetained bool             `json:"reservation_retained,omitempty"`
	Status              Status           `json:"status"`
	CreatedAt           time.Time        `json:"created_at"`
	PendingExpiresAt    time.Time        `json:"pending_expires_at"`
	ExpiresAt           time.Time        `json:"expires_at,omitempty"`
	ReservedAt          time.Time        `json:"reserved_at,omitempty"`
	DecidedAt           time.Time        `json:"decided_at,omitempty"`
	DecidedBy           string           `json:"decided_by,omitempty"`
	UsedAt              time.Time        `json:"used_at,omitempty"`
	ExpiredFrom         Status           `json:"expired_from,omitempty"`
	Notifier            *NotifierMessage `json:"notifier,omitempty"`
	NotifierStatus      string           `json:"notifier_status,omitempty"`
	NotifierClaimedAt   time.Time        `json:"notifier_claimed_at,omitempty"`
}

// ExpiredGrant is one grant that became or remains expired and may need a
// notification update.
type ExpiredGrant struct {
	Grant        Grant
	ExpiredFrom  Status
	NeedsMessage bool
}

// StatusUpdate is one grant notification status that needs to be refreshed.
type StatusUpdate struct {
	Grant          Grant
	Status         Status
	NotifierStatus string
}

// NotifierStatusKey returns the persisted status key for this notification.
func (u StatusUpdate) NotifierStatusKey() string {
	if u.NotifierStatus != "" {
		return u.NotifierStatus
	}
	if u.Status == NotifierStatusReserved {
		return retainedReservationNotifierStatus(u.Grant)
	}
	return string(u.Status)
}

// Store owns the grant file.
type Store struct {
	path string
	opts Options

	mu sync.Mutex
}

type fileData struct {
	Grants []Grant `json:"grants"`
}

type normalizedRequest struct {
	ClientRequestID string
	Reason          string
	Duration        time.Duration
	Minutes         int
	MaxUses         int
}

// New returns a grant store rooted at path.
func New(path string, opts Options) *Store {
	if opts.PendingTimeout <= 0 {
		opts.PendingTimeout = DefaultPendingTimeout
	}
	if opts.DefaultDuration <= 0 {
		opts.DefaultDuration = DefaultDuration
	}
	if opts.MaxDuration <= 0 {
		opts.MaxDuration = MaxDuration
	}
	if opts.ReservationTimeout <= 0 {
		opts.ReservationTimeout = DefaultReservationTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{path: path, opts: opts}
}

// Request creates a pending grant. The returned boolean reports whether a new
// grant was created; false means an existing idempotent request was returned.
func (s *Store) Request(req Request) (Grant, bool, error) {
	normalized, err := s.normalizeRequest(req)
	if err != nil {
		return Grant{}, false, err
	}
	return s.createRequest(req, normalized, s.opts.Now().UTC())
}

// Get returns one grant by id.
func (s *Store) Get(id string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Grant{}, err
	}
	expired := s.expireGrants(&data)
	_, grant, err := s.findGrant(&data, id)
	if err != nil {
		return Grant{}, err
	}
	if len(expired) > 0 {
		if err := s.save(data); err != nil {
			return Grant{}, err
		}
	}
	return grant, nil
}

func (s *Store) normalizeRequest(req Request) (normalizedRequest, error) {
	duration, minutes, err := s.requestDuration(req.RequestedDuration)
	if err != nil {
		return normalizedRequest{}, err
	}
	maxUses, err := requestMaxUses(req.MaxUses)
	if err != nil {
		return normalizedRequest{}, err
	}
	clientRequestID, err := normalizeClientRequestID(req.ClientRequestID)
	if err != nil {
		return normalizedRequest{}, err
	}
	reason, err := normalizeReason(req.Reason)
	if err != nil {
		return normalizedRequest{}, err
	}
	return normalizedRequest{
		ClientRequestID: clientRequestID,
		Reason:          reason,
		Duration:        duration,
		Minutes:         minutes,
		MaxUses:         maxUses,
	}, nil
}

func normalizeReason(value string) (string, error) {
	reason := strings.TrimSpace(value)
	if reason == "" {
		return "", errors.New("grant reason is required")
	}
	if len(reason) > 512 {
		return "", errors.New("grant reason is longer than 512 bytes")
	}
	return reason, nil
}

func (s *Store) createRequest(req Request, normalized normalizedRequest, now time.Time) (Grant, bool, error) {
	var grant Grant
	created := false
	if err := s.update(func(data *fileData) error {
		if existing, ok := findIdempotentRequest(data, req.Client, normalized.ClientRequestID); ok {
			grant = existing
			return nil
		}
		next, err := newGrant(req, normalized, now, s.opts.PendingTimeout)
		if err != nil {
			return err
		}
		grant = next
		data.Grants = append(data.Grants, grant)
		created = true
		return nil
	}); err != nil {
		return Grant{}, false, err
	}
	return grant, created, nil
}

func findIdempotentRequest(data *fileData, client, clientRequestID string) (Grant, bool) {
	if clientRequestID == "" {
		return Grant{}, false
	}
	return findClientRequest(data, client, clientRequestID)
}

func newGrant(req Request, normalized normalizedRequest, now time.Time, pendingTimeout time.Duration) (Grant, error) {
	id, err := randomID(16)
	if err != nil {
		return Grant{}, err
	}
	decisionToken, err := randomID(8)
	if err != nil {
		return Grant{}, err
	}
	return Grant{
		ID:               id,
		DecisionToken:    decisionToken,
		Client:           req.Client,
		ClientRequestID:  normalized.ClientRequestID,
		Operation:        req.Operation,
		Target:           req.Target,
		Ref:              req.Ref,
		Reason:           normalized.Reason,
		RequestedMinutes: normalized.Minutes,
		MaxUses:          normalized.MaxUses,
		Status:           StatusPending,
		CreatedAt:        now,
		PendingExpiresAt: now.Add(pendingTimeout),
		ExpiresAt:        now.Add(normalized.Duration),
	}, nil
}

// Approve activates a pending grant.
func (s *Store) Approve(id, decisionToken, actor string) (Grant, error) {
	return s.decide(id, decisionToken, actor, StatusActive)
}

// Deny denies a pending grant.
func (s *Store) Deny(id, decisionToken, actor string) (Grant, error) {
	return s.decide(id, decisionToken, actor, StatusDenied)
}

func (s *Store) decide(id, decisionToken, actor string, status Status) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := s.pendingGrant(data, id, decisionToken)
		if err != nil {
			return err
		}
		now := s.opts.Now().UTC()
		if !now.Before(grant.PendingExpiresAt) {
			grant.Status = StatusExpired
			grant.DecidedAt = now
			data.Grants[index] = grant
			return ErrNotPending
		}
		grant.Status = status
		grant.DecidedAt = now
		grant.DecidedBy = actor
		if status == StatusActive {
			grant.ExpiresAt = now.Add(time.Duration(grant.RequestedMinutes) * time.Minute)
			if grant.MaxUses <= 0 {
				grant.MaxUses = DefaultMaxUses
			}
		}
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

func (s *Store) pendingGrant(data *fileData, id, decisionToken string) (int, Grant, error) {
	index, grant, err := s.findGrant(data, id)
	if err != nil {
		return -1, Grant{}, err
	}
	if grant.DecisionToken != decisionToken {
		return -1, Grant{}, ErrInvalidDecisionToken
	}
	if grant.Status != StatusPending {
		return -1, Grant{}, ErrNotPending
	}
	return index, grant, nil
}

// Cancel marks a pending grant canceled, usually after notification failure.
func (s *Store) Cancel(id string) error {
	return s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		if grant.Status != StatusPending {
			return nil
		}
		grant.Status = StatusCanceled
		grant.DecidedAt = s.opts.Now().UTC()
		grant.NotifierClaimedAt = time.Time{}
		data.Grants[index] = grant
		return nil
	})
}

// CancelIfNotifierClaimed marks a pending grant canceled only when the current
// notifier claim still matches claimedAt.
func (s *Store) CancelIfNotifierClaimed(id string, claimedAt time.Time) (Grant, bool, error) {
	var out Grant
	canceled := false
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		out = grant
		if grant.Status != StatusPending || !grant.NotifierClaimedAt.Equal(claimedAt) {
			return nil
		}
		grant.Status = StatusCanceled
		grant.DecidedAt = s.opts.Now().UTC()
		grant.NotifierClaimedAt = time.Time{}
		data.Grants[index] = grant
		out = grant
		canceled = true
		return nil
	})
	return out, canceled, err
}

// ClaimNotifier reserves responsibility for sending the operator notification.
// A stale claim may be reclaimed after lease has elapsed.
func (s *Store) ClaimNotifier(id string, lease time.Duration) (Grant, bool, error) {
	var out Grant
	claimed := false
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		out = grant
		if !grantNeedsNotificationClaim(grant) {
			return nil
		}
		now := s.opts.Now().UTC()
		if !grant.NotifierClaimedAt.IsZero() && now.Before(grant.NotifierClaimedAt.Add(lease)) {
			return nil
		}
		grant.NotifierClaimedAt = now
		data.Grants[index] = grant
		out = grant
		claimed = true
		return nil
	})
	return out, claimed, err
}

// SetNotifier records the editable operator notification for a grant.
func (s *Store) SetNotifier(id string, message NotifierMessage) (Grant, error) {
	grant, _, err := s.setNotifier(id, time.Time{}, message, false)
	return grant, err
}

// SetNotifierIfClaimed records the notification only if the current notifier
// claim matches claimedAt. It prevents stale send attempts from overwriting a
// notification created after their claim was reclaimed.
func (s *Store) SetNotifierIfClaimed(id string, claimedAt time.Time, message NotifierMessage) (Grant, bool, error) {
	return s.setNotifier(id, claimedAt, message, true)
}

func (s *Store) setNotifier(id string, claimedAt time.Time, message NotifierMessage, requireClaim bool) (Grant, bool, error) {
	var out Grant
	recorded := false
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		out = grant
		if requireClaim && !grant.NotifierClaimedAt.Equal(claimedAt) {
			return nil
		}
		grant.Notifier = &message
		grant.NotifierStatus = string(StatusPending)
		grant.NotifierClaimedAt = time.Time{}
		data.Grants[index] = grant
		out = grant
		recorded = true
		return nil
	})
	return out, recorded, err
}

// MarkNotifierStatus records that the operator notification shows status.
func (s *Store) MarkNotifierStatus(id, status string) error {
	return s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		grant.NotifierStatus = status
		data.Grants[index] = grant
		return nil
	})
}

// ReserveUse durably reserves one use before forwarding a dangerous operation
// upstream. Reserved uses count against the budget until committed or released.
func (s *Store) ReserveUse(id string) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		if !grantCanReserveUse(grant) {
			return ErrNotActive
		}
		if grant.ReservedCount == 0 {
			grant.ReservedAt = s.opts.Now().UTC()
		}
		grant.ReservedCount++
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

// RetainUse marks a reserved use as needing operator review after an ambiguous
// upstream result.
func (s *Store) RetainUse(id string) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		if !grantCanCommitUse(grant) {
			return ErrNotActive
		}
		grant.ReservationRetained = true
		if grant.ReservedAt.IsZero() {
			grant.ReservedAt = s.opts.Now().UTC()
		}
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

// CommitUse converts one reserved use into an accepted use.
func (s *Store) CommitUse(id string) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		if !grantCanCommitUse(grant) {
			return ErrNotActive
		}
		grant.ReservedCount--
		grant.UsedAt = s.opts.Now().UTC()
		grant.UsedCount++
		if grant.ReservedCount == 0 {
			grant.ReservationRetained = false
			grant.ReservedAt = time.Time{}
		}
		if grant.UsedCount >= grantMaxUses(grant) {
			grant.Status = StatusConsumed
			grant.ExpiredFrom = ""
		}
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

// ReleaseUse releases one reserved use after an upstream rejection or error.
func (s *Store) ReleaseUse(id string) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		if grant.ReservedCount <= 0 {
			out = grant
			return nil
		}
		grant.ReservedCount--
		if grant.ReservedCount == 0 {
			grant.ReservationRetained = false
			grant.ReservedAt = time.Time{}
		}
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

// MatchActive returns an active grant for client, operation, target, and ref.
func (s *Store) MatchActive(client, operation, target, ref string) (Grant, bool, error) {
	var out Grant
	found := false
	err := s.update(func(data *fileData) error {
		for _, grant := range data.Grants {
			if grantMatchesActive(grant, client, operation, target, ref) {
				out = grant
				found = true
				return nil
			}
		}
		return nil
	})
	return out, found, err
}

// RecordUse records that an active grant was used.
func (s *Store) RecordUse(id string) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := s.findGrant(data, id)
		if err != nil {
			return err
		}
		if grant.Status != StatusActive {
			return ErrNotActive
		}
		if grant.UsedCount+grant.ReservedCount >= grantMaxUses(grant) {
			return ErrNotActive
		}
		grant.UsedAt = s.opts.Now().UTC()
		grant.UsedCount++
		if grant.UsedCount >= grantMaxUses(grant) {
			grant.Status = StatusConsumed
		}
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

// ExpireDue marks due grants expired and returns expired grants whose
// notifications have not yet been updated to the expired status.
func (s *Store) ExpireDue() ([]ExpiredGrant, error) {
	updates, err := s.StatusUpdatesDue()
	if err != nil {
		return nil, err
	}
	var expired []ExpiredGrant
	for _, update := range updates {
		if update.Status == StatusExpired {
			expired = append(expired, ExpiredGrant{Grant: update.Grant, ExpiredFrom: update.Grant.ExpiredFrom, NeedsMessage: true})
		}
	}
	return expired, nil
}

// StatusUpdatesDue marks due grants expired and returns grants whose
// notifications have not yet been updated to their latest status.
func (s *Store) StatusUpdatesDue() ([]StatusUpdate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	changed := len(s.expireGrants(&data)) > 0
	if s.retainStaleReservations(&data) {
		changed = true
	}
	due := statusUpdatesNeedingMessage(data.Grants)
	if changed {
		if err := s.save(data); err != nil {
			return nil, err
		}
	}
	return due, nil
}

func (s *Store) requestDuration(requested time.Duration) (time.Duration, int, error) {
	duration := requested
	if duration <= 0 {
		duration = s.opts.DefaultDuration
	}
	if duration > s.opts.MaxDuration {
		return 0, 0, fmt.Errorf("grant duration exceeds %d minutes", int(s.opts.MaxDuration/time.Minute))
	}
	minutes := int(duration / time.Minute)
	if minutes <= 0 || time.Duration(minutes)*time.Minute != duration {
		return 0, 0, errors.New("grant duration must be a positive whole number of minutes")
	}
	return duration, minutes, nil
}

func requestMaxUses(requested int) (int, error) {
	if requested < 0 {
		return 0, errors.New("grant max uses must be positive")
	}
	if requested == 0 {
		return DefaultMaxUses, nil
	}
	if requested > MaxUses {
		return 0, fmt.Errorf("grant max uses exceeds %d", MaxUses)
	}
	return requested, nil
}

func normalizeClientRequestID(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if len(value) > 128 || strings.ContainsAny(value, " \t\r\n") {
		return "", errors.New("client_request_id must be 1-128 non-whitespace bytes")
	}
	return value, nil
}

func (s *Store) update(fn func(*fileData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return err
	}
	changed := s.pruneExpired(&data)
	if err := fn(&data); err != nil {
		if changed {
			_ = s.save(data)
		}
		return err
	}
	return s.save(data)
}

func (s *Store) load() (fileData, error) {
	raw, err := os.ReadFile(s.path) // #nosec G304 -- operator-configured state path.
	if errors.Is(err, os.ErrNotExist) {
		return fileData{}, nil
	}
	if err != nil {
		return fileData{}, fmt.Errorf("read grants store: %w", err)
	}
	var data fileData
	if err := json.Unmarshal(raw, &data); err != nil {
		return fileData{}, fmt.Errorf("parse grants store: %w", err)
	}
	for i := range data.Grants {
		normalizeLoadedGrant(&data.Grants[i])
	}
	return data, nil
}

func normalizeLoadedGrant(grant *Grant) {
	legacyUseBudget := grant.MaxUses <= 0
	if legacyUseBudget {
		grant.MaxUses = DefaultMaxUses
	}
	if grant.ReservedCount < 0 {
		grant.ReservedCount = 0
	}
	if grant.ReservedCount == 0 {
		grant.ReservationRetained = false
		grant.ReservedAt = time.Time{}
	}
	if legacyUseBudget && grant.Status == StatusActive && !grant.UsedAt.IsZero() && grant.UsedCount == 0 {
		grant.UsedCount = grant.MaxUses
		grant.Status = StatusConsumed
	}
}

func (s *Store) save(data fileData) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create grants store parent: %w", err)
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("encode grants store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(raw, '\n'), 0o600); err != nil {
		return fmt.Errorf("write grants store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("replace grants store: %w", err)
	}
	return nil
}

func (s *Store) pruneExpired(data *fileData) bool {
	return len(s.expireGrants(data)) > 0
}

func (s *Store) retainStaleReservations(data *fileData) bool {
	now := s.opts.Now().UTC()
	changed := false
	for i := range data.Grants {
		grant := data.Grants[i]
		if !grantHasStaleReservation(grant, now, s.opts.ReservationTimeout) {
			continue
		}
		grant.ReservationRetained = true
		if grant.ReservedAt.IsZero() {
			grant.ReservedAt = now
		}
		data.Grants[i] = grant
		changed = true
	}
	return changed
}

func (s *Store) expireGrants(data *fileData) []ExpiredGrant {
	now := s.opts.Now().UTC()
	var expired []ExpiredGrant
	for i := range data.Grants {
		grant := data.Grants[i]
		switch grant.Status {
		case StatusPending:
			if !now.Before(grant.PendingExpiresAt) {
				previous := grant.Status
				grant.Status = StatusExpired
				grant.ExpiredFrom = previous
				grant.DecidedAt = now
				expired = append(expired, ExpiredGrant{Grant: grant, ExpiredFrom: previous, NeedsMessage: grantNeedsExpiredMessage(grant)})
			}
		case StatusActive:
			if !now.Before(grant.ExpiresAt) {
				previous := grant.Status
				grant.Status = StatusExpired
				grant.ExpiredFrom = previous
				expired = append(expired, ExpiredGrant{Grant: grant, ExpiredFrom: previous, NeedsMessage: grantNeedsExpiredMessage(grant)})
			}
		}
		data.Grants[i] = grant
	}
	return expired
}

func statusUpdatesNeedingMessage(grants []Grant) []StatusUpdate {
	var out []StatusUpdate
	for _, grant := range grants {
		update, ok := statusUpdateNeedingMessage(grant)
		if ok {
			out = append(out, update)
		}
	}
	return out
}

func statusUpdateNeedingMessage(grant Grant) (StatusUpdate, bool) {
	if grantHasRetainedReservation(grant) {
		update := retainedReservationStatusUpdate(grant)
		return update, grantNeedsStatusMessage(grant, update.NotifierStatusKey())
	}
	if grantHasExpiredUse(grant) {
		update := expiredUseStatusUpdate(grant)
		return update, grantNeedsStatusMessage(grant, update.NotifierStatusKey())
	}
	update := StatusUpdate{Grant: grant, Status: grant.Status}
	return update, grantNeedsLifecycleStatusMessage(grant)
}

func grantNeedsLifecycleStatusMessage(grant Grant) bool {
	switch grant.Status {
	case StatusActive:
		return grantNeedsActiveMessage(grant)
	case StatusDenied, StatusExpired, StatusConsumed:
		return grantNeedsStatusMessage(grant, string(grant.Status))
	default:
		return false
	}
}

func grantNeedsExpiredMessage(grant Grant) bool {
	return grantNeedsStatusMessage(grant, string(StatusExpired))
}

func grantNeedsPendingDecisionMessage(grant Grant) bool {
	return grant.Notifier != nil &&
		grant.Notifier.MessageID != 0 &&
		(grant.NotifierStatus == "" || grant.NotifierStatus == string(StatusPending))
}

func grantNeedsActiveMessage(grant Grant) bool {
	return grantNeedsPendingDecisionMessage(grant) ||
		(grant.Notifier != nil && grant.Notifier.MessageID != 0 && strings.HasPrefix(grant.NotifierStatus, string(NotifierStatusReserved)))
}

func grantNeedsStatusMessage(grant Grant, status string) bool {
	return grant.Notifier != nil && grant.Notifier.MessageID != 0 && grant.NotifierStatus != status
}

func grantHasRetainedReservation(grant Grant) bool {
	return grant.ReservationRetained && grant.ReservedCount > 0 && (grant.Status == StatusActive || grant.Status == StatusExpired)
}

func grantHasStaleReservation(grant Grant, now time.Time, timeout time.Duration) bool {
	if grant.ReservationRetained || grant.ReservedCount <= 0 || (grant.Status != StatusActive && grant.Status != StatusExpired) {
		return false
	}
	return grant.ReservedAt.IsZero() || !now.Before(grant.ReservedAt.Add(timeout))
}

func retainedReservationStatusUpdate(grant Grant) StatusUpdate {
	return newStatusUpdate(grant, NotifierStatusReserved, retainedReservationNotifierStatus(grant))
}

func retainedReservationNotifierStatus(grant Grant) string {
	return string(NotifierStatusReserved) + ":" + string(grant.Status)
}

func grantHasExpiredUse(grant Grant) bool {
	return grant.Status == StatusExpired && grant.UsedCount > 0 && grant.ReservedCount == 0
}

func expiredUseStatusUpdate(grant Grant) StatusUpdate {
	return newStatusUpdate(grant, StatusConsumed, string(NotifierStatusUsedExpired))
}

func newStatusUpdate(grant Grant, status Status, notifierStatus string) StatusUpdate {
	return StatusUpdate{
		Grant:          grant,
		Status:         status,
		NotifierStatus: notifierStatus,
	}
}

func grantNeedsNotificationClaim(grant Grant) bool {
	return grant.Status == StatusPending && grant.Notifier == nil
}

func (s *Store) findGrant(data *fileData, id string) (int, Grant, error) {
	for i, grant := range data.Grants {
		if grant.ID == id {
			return i, grant, nil
		}
	}
	return -1, Grant{}, ErrNotFound
}

func findClientRequest(data *fileData, client, clientRequestID string) (Grant, bool) {
	for i := len(data.Grants) - 1; i >= 0; i-- {
		grant := data.Grants[i]
		if grant.Client == client && grant.ClientRequestID == clientRequestID {
			if grant.Status == StatusCanceled {
				continue
			}
			return grant, true
		}
	}
	return Grant{}, false
}

func grantMatchesActive(grant Grant, client, operation, target, ref string) bool {
	return grant.Status == StatusActive &&
		grant.Client == client &&
		grant.Operation == operation &&
		grant.Target == target &&
		grant.Ref == ref &&
		grant.UsedCount+grant.ReservedCount < grantMaxUses(grant)
}

func grantCanReserveUse(grant Grant) bool {
	return grant.Status == StatusActive &&
		grant.UsedCount+grant.ReservedCount < grantMaxUses(grant)
}

func grantCanCommitUse(grant Grant) bool {
	return grant.ReservedCount > 0 && (grant.Status == StatusActive || grant.Status == StatusExpired)
}

func grantMaxUses(grant Grant) int {
	if grant.MaxUses <= 0 {
		return DefaultMaxUses
	}
	return grant.MaxUses
}

func randomID(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate grant id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
