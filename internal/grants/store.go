// Package grants adapts Hugging Face grant fields to brokerkit's durable
// approval lifecycle.
package grants

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	bkgrants "github.com/osolmaz/brokerkit/grants"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
)

const (
	DefaultPendingTimeout     = 10 * time.Minute
	DefaultDuration           = 5 * time.Minute
	MaxDuration               = time.Hour
	DefaultMaxUses            = 1
	MaxUses                   = 25
	DefaultReservationTimeout = 5 * time.Minute

	ModeWindow    = "window"
	ModeExecution = "execution"

	metadataMode = "hf_grant_mode"
	targetName   = "name"
	targetRef    = "ref"
)

// Status is the lifecycle state of one grant request.
type Status = bkgrants.Status

// Grant lifecycle states.
const (
	StatusPending  = bkgrants.StatusPending
	StatusActive   = bkgrants.StatusActive
	StatusDenied   = bkgrants.StatusDenied
	StatusExpired  = bkgrants.StatusExpired
	StatusCanceled = bkgrants.StatusCanceled
	StatusConsumed = bkgrants.StatusConsumed
	StatusRevoked  = bkgrants.StatusRevoked
)

const (
	NotifierStatusReserved    Status = bkgrants.NotificationStatusReserved
	NotifierStatusUsed        Status = bkgrants.NotificationStatusUsed
	NotifierStatusUsedExpired Status = bkgrants.NotificationStatusUsedExpired
)

var (
	ErrNotFound             = bkgrants.ErrNotFound
	ErrInvalidDecisionToken = bkgrants.ErrInvalidDecisionToken
	ErrNotPending           = bkgrants.ErrNotPending
	ErrNotActive            = bkgrants.ErrNotActive
	ErrIdempotencyConflict  = bkgrants.ErrIdempotencyConflict
)

// Options configures a Store.
type Options struct {
	PendingTimeout     time.Duration
	DefaultDuration    time.Duration
	MaxDuration        time.Duration
	ReservationTimeout time.Duration
	Now                func() time.Time
}

// Request is one requested HF grant.
type Request struct {
	Client            string
	ClientRequestID   string
	Operation         string
	Mode              string
	Target            string
	Ref               string
	Attrs             map[string]any
	Reason            string
	RequestedDuration time.Duration
	PendingTimeout    time.Duration
	MaxUses           int
}

// NotifierMessage identifies one editable operator notification.
type NotifierMessage = bkgrants.MessageRef

// Grant is the HF-facing view of one brokerkit grant.
type Grant struct {
	ID                  string           `json:"id"`
	DecisionToken       string           `json:"-"`
	Client              string           `json:"client"`
	ClientRequestID     string           `json:"client_request_id,omitempty"`
	Operation           string           `json:"operation"`
	Mode                string           `json:"mode,omitempty"`
	Target              string           `json:"target"`
	Ref                 string           `json:"ref"`
	Attrs               map[string]any   `json:"attrs,omitempty"`
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
	NotifierClaimUntil  time.Time        `json:"notifier_claim_until,omitempty"`
	NotifierUnresolved  bool             `json:"notifier_unresolved,omitempty"`
}

// ExpiredGrant is one expired grant with a pending notification update.
type ExpiredGrant struct {
	Grant        Grant
	ExpiredFrom  Status
	NeedsMessage bool
}

// StatusUpdate is one durable operator-message update.
type StatusUpdate struct {
	Grant          Grant
	Status         Status
	NotifierStatus string
}

// NotifierStatusKey returns the exact durable delivery revision.
func (u StatusUpdate) NotifierStatusKey() string {
	if u.NotifierStatus != "" {
		return u.NotifierStatus
	}
	return string(u.Status)
}

// Store delegates all generic state transitions to brokerkit.
type Store struct {
	core            *bkgrants.Store
	defaultDuration time.Duration
	maxDuration     time.Duration
}

// New returns an HF grant adapter rooted at path.
func New(path string, opts Options) *Store {
	defaultGrantDuration := defaultDuration(opts.DefaultDuration, DefaultDuration)
	maxGrantDuration := defaultDuration(opts.MaxDuration, MaxDuration)
	return &Store{
		core: bkgrants.New(path, bkgrants.Options{
			PendingTimeout:     defaultDuration(opts.PendingTimeout, DefaultPendingTimeout),
			DefaultDuration:    defaultGrantDuration,
			MaxDuration:        maxGrantDuration,
			ReservationTimeout: defaultDuration(opts.ReservationTimeout, DefaultReservationTimeout),
			Now:                opts.Now,
		}),
		defaultDuration: defaultGrantDuration,
		maxDuration:     maxGrantDuration,
	}
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value <= 0 {
		return fallback
	}
	return value
}

// Request validates HF fields and creates or finds a brokerkit grant.
func (s *Store) Request(req Request) (Grant, bool, error) {
	coreRequest, err := s.toCoreRequest(req)
	if err != nil {
		return Grant{}, false, err
	}
	result, created, err := s.core.Request(coreRequest)
	if err != nil {
		return Grant{}, false, err
	}
	grant, err := fromCoreGrant(result.Grant, result.DecisionToken)
	return grant, created, err
}

func (s *Store) toCoreRequest(req Request) (bkgrants.Request, error) {
	clientRequestID, reason, mode, duration, maxUses, attrs, err := s.normalizeRequest(req)
	if err != nil {
		return bkgrants.Request{}, err
	}
	fields := map[string][]string{targetName: {req.Target}}
	if req.Ref != "" {
		fields[targetRef] = []string{req.Ref}
	}
	return bkgrants.Request{
		Client:          req.Client,
		ClientRequestID: clientRequestID,
		Operation:       req.Operation,
		Target:          bkpolicy.Target{Kind: "hf", Fields: fields},
		Attrs:           attrs,
		Metadata:        map[string]string{metadataMode: mode},
		Reason:          reason,
		Duration:        duration,
		PendingTimeout:  req.PendingTimeout,
		MaxUses:         maxUses,
	}, nil
}

func (s *Store) normalizeRequest(req Request) (string, string, string, time.Duration, int, map[string][]string, error) {
	clientRequestID, reason, err := normalizeRequestIdentity(req)
	if err != nil {
		return "", "", "", 0, 0, nil, err
	}
	mode, duration, maxUses, err := s.normalizeRequestGrant(req)
	if err != nil {
		return "", "", "", 0, 0, nil, err
	}
	attrs, err := encodeAttrs(req.Attrs)
	return clientRequestID, reason, mode, duration, maxUses, attrs, err
}

func normalizeRequestIdentity(req Request) (string, string, error) {
	if req.Client == "" || req.Operation == "" || req.Target == "" {
		return "", "", errors.New("client, operation, and target are required")
	}
	clientRequestID, err := normalizeClientRequestID(req.ClientRequestID)
	if err != nil {
		return "", "", err
	}
	reason, err := normalizeReason(req.Reason)
	return clientRequestID, reason, err
}

func (s *Store) normalizeRequestGrant(req Request) (string, time.Duration, int, error) {
	mode, err := normalizeMode(req.Mode)
	if err != nil {
		return "", 0, 0, err
	}
	duration, err := normalizeRequestedDuration(req.RequestedDuration, s.defaultDuration, s.maxDuration)
	if err != nil {
		return "", 0, 0, err
	}
	maxUses, err := normalizeMaxUses(req.MaxUses)
	return mode, duration, maxUses, err
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

func normalizeReason(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("grant reason is required")
	}
	if len(value) > 512 {
		return "", errors.New("grant reason is longer than 512 bytes")
	}
	return value, nil
}

func normalizeMode(value string) (string, error) {
	switch value {
	case "", ModeWindow:
		return ModeWindow, nil
	case ModeExecution:
		return ModeExecution, nil
	default:
		return "", errors.New("grant mode is invalid")
	}
}

func normalizeRequestedDuration(value, fallback, maximum time.Duration) (time.Duration, error) {
	if value <= 0 {
		return fallback, nil
	}
	if value > maximum {
		return 0, fmt.Errorf("grant duration exceeds %d minutes", int(maximum/time.Minute))
	}
	if value%time.Minute != 0 {
		return 0, errors.New("grant duration must be a positive whole number of minutes")
	}
	return value, nil
}

func normalizeMaxUses(value int) (int, error) {
	if value < 0 {
		return 0, errors.New("grant max uses must be positive")
	}
	if value == 0 {
		return DefaultMaxUses, nil
	}
	if value > MaxUses {
		return 0, fmt.Errorf("grant max uses exceeds %d", MaxUses)
	}
	return value, nil
}

func encodeAttrs(attrs map[string]any) (map[string][]string, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	out := make(map[string][]string, len(attrs))
	for key, value := range attrs {
		data, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("grant attr %q is invalid: %w", key, err)
		}
		out[key] = []string{string(data)}
	}
	return out, nil
}

func decodeAttrs(attrs map[string][]string) (map[string]any, error) {
	if len(attrs) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(attrs))
	for key, values := range attrs {
		if len(values) != 1 {
			return nil, fmt.Errorf("stored grant attr %q is invalid", key)
		}
		decoder := json.NewDecoder(bytes.NewBufferString(values[0]))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			return nil, fmt.Errorf("decode stored grant attr %q: %w", key, err)
		}
		if number, ok := value.(json.Number); ok {
			if integer, err := number.Int64(); err == nil {
				value = integer
			}
		}
		out[key] = value
	}
	return out, nil
}

func fromCoreGrant(grant bkgrants.Grant, decisionToken string) (Grant, error) {
	attrs, err := decodeAttrs(grant.Attrs)
	if err != nil {
		return Grant{}, err
	}
	return Grant{
		ID:                  grant.ID,
		DecisionToken:       decisionToken,
		Client:              grant.Client,
		ClientRequestID:     grant.ClientRequestID,
		Operation:           grant.Operation,
		Mode:                grant.Metadata[metadataMode],
		Target:              bkpolicy.FirstValue(grant.Target.Fields[targetName]),
		Ref:                 bkpolicy.FirstValue(grant.Target.Fields[targetRef]),
		Attrs:               attrs,
		Reason:              grant.Reason,
		RequestedMinutes:    int(grant.Duration / time.Minute),
		MaxUses:             grant.MaxUses,
		UsedCount:           grant.UsedCount,
		ReservedCount:       grant.ReservedCount,
		ReservationRetained: grant.ReservationRetained,
		Status:              grant.Status,
		CreatedAt:           grant.CreatedAt,
		PendingExpiresAt:    grant.PendingExpiresAt,
		ExpiresAt:           grant.ExpiresAt,
		ReservedAt:          grant.ReservedAt,
		DecidedAt:           grant.DecidedAt,
		DecidedBy:           grant.DecidedBy,
		UsedAt:              grant.UsedAt,
		ExpiredFrom:         grant.ExpiredFrom,
		Notifier:            grant.Notification,
		NotifierStatus:      grant.NotificationStatus,
		NotifierClaimedAt:   grant.NotificationClaimedAt,
		NotifierClaimUntil:  grant.NotificationClaimUntil,
		NotifierUnresolved:  grant.NotificationDeliveryUnresolved,
	}, nil
}

// Get returns one grant by id.
func (s *Store) Get(id string) (Grant, error) {
	grant, err := s.core.Get(id)
	if err != nil {
		return Grant{}, err
	}
	return fromCoreGrant(grant, "")
}

// GetForClient returns one grant only when it belongs to client.
func (s *Store) GetForClient(client, id string) (Grant, error) {
	grant, err := s.Get(id)
	if err != nil || grant.Client != client {
		return Grant{}, ErrNotFound
	}
	return grant, nil
}

// ListForClient returns all grants for one HF client.
func (s *Store) ListForClient(client string) ([]Grant, error) {
	values, err := s.core.ListForClient(client)
	if err != nil {
		return nil, err
	}
	return fromCoreGrants(values)
}

func fromCoreGrants(values []bkgrants.Grant) ([]Grant, error) {
	out := make([]Grant, 0, len(values))
	for _, value := range values {
		grant, err := fromCoreGrant(value, "")
		if err != nil {
			return nil, err
		}
		out = append(out, grant)
	}
	return out, nil
}

// Cancel closes a pending grant after notification failure.
func (s *Store) Cancel(id string) error { return s.core.Cancel(id) }

// CancelIfNotifierClaimed cancels only the current delivery claim.
func (s *Store) CancelIfNotifierClaimed(id string, claimedAt time.Time) (Grant, bool, error) {
	return changeNotifierClaim(s.core.CancelIfNotificationClaimed, id, claimedAt)
}

// RetainNotifierClaim marks the current notification send as ambiguous.
func (s *Store) RetainNotifierClaim(id string, claimedAt time.Time) (Grant, bool, error) {
	return changeNotifierClaim(s.core.RetainNotificationClaim, id, claimedAt)
}

func changeNotifierClaim(change func(string, time.Time) (bkgrants.Grant, bool, error), id string, claimedAt time.Time) (Grant, bool, error) {
	grant, changed, err := change(id, claimedAt)
	if err != nil {
		return Grant{}, false, err
	}
	out, err := fromCoreGrant(grant, "")
	return out, changed, err
}

// ClaimNotifier leases notification delivery and returns a fresh raw token.
func (s *Store) ClaimNotifier(id string, lease time.Duration) (Grant, bool, error) {
	claim, claimed, err := s.core.ClaimNotification(id, lease)
	if err != nil {
		return Grant{}, false, err
	}
	grant, err := fromCoreGrant(claim.Grant, claim.DecisionToken)
	return grant, claimed, err
}

// SetNotifier records one editable operator notification.
func (s *Store) SetNotifier(id string, message NotifierMessage) (Grant, error) {
	grant, err := s.core.SetNotification(id, message)
	if err != nil {
		return Grant{}, err
	}
	return fromCoreGrant(grant, "")
}

// SetNotifierIfClaimed records a notification only for the current claim.
func (s *Store) SetNotifierIfClaimed(id string, claimedAt time.Time, message NotifierMessage) (Grant, bool, error) {
	grant, recorded, err := s.core.SetNotificationIfClaimed(id, claimedAt, message)
	if err != nil {
		return Grant{}, false, err
	}
	out, err := fromCoreGrant(grant, "")
	return out, recorded, err
}

// MarkNotifierStatus records successful delivery of one status revision.
func (s *Store) MarkNotifierStatus(id, status string) error {
	return s.core.MarkNotificationStatus(id, status)
}

// ReserveUse durably reserves one approved use.
func (s *Store) ReserveUse(id string) (Grant, error) { return s.changeUse(s.core.ReserveUse, id) }

// RetainUse preserves an ambiguous reservation for operator review.
func (s *Store) RetainUse(id string) (Grant, error) { return s.changeUse(s.core.RetainUse, id) }

// CommitUse spends one reserved use.
func (s *Store) CommitUse(id string) (Grant, error) { return s.changeUse(s.core.CommitUse, id) }

// ReleaseUse returns one reservation to the available budget.
func (s *Store) ReleaseUse(id string) (Grant, error) { return s.changeUse(s.core.ReleaseUse, id) }

func (s *Store) changeUse(change func(string) (bkgrants.Grant, error), id string) (Grant, error) {
	grant, err := change(id)
	if err != nil {
		return Grant{}, err
	}
	return fromCoreGrant(grant, "")
}

// RecordUse reserves and commits one use for legacy call sites.
func (s *Store) RecordUse(id string) (Grant, error) {
	if _, err := s.core.ReserveUse(id); err != nil {
		return Grant{}, err
	}
	grant, err := s.core.CommitUse(id)
	if err != nil {
		_, _ = s.core.ReleaseUse(id)
		return Grant{}, err
	}
	return fromCoreGrant(grant, "")
}

// MatchActive returns an exact active HF grant.
func (s *Store) MatchActive(client, operation, target, ref string) (Grant, bool, error) {
	return s.MatchActiveFunc(client, operation, target, ref, nil)
}

// MatchActiveFunc also applies one HF-specific matcher.
func (s *Store) MatchActiveFunc(client, operation, target, ref string, match func(Grant) bool) (Grant, bool, error) {
	values, err := s.ListForClient(client)
	if err != nil {
		return Grant{}, false, err
	}
	for _, grant := range values {
		if activeGrantMatches(grant, operation, target, ref, match) {
			return grant, true, nil
		}
	}
	return Grant{}, false, nil
}

func activeGrantMatches(grant Grant, operation, target, ref string, match func(Grant) bool) bool {
	return grant.Status == StatusActive && !grant.ReservationRetained && grant.Operation == operation && grant.Target == target && grant.Ref == ref &&
		grant.UsedCount+grant.ReservedCount < grant.MaxUses && (match == nil || match(grant))
}

// StatusUpdatesDue returns brokerkit's durable delivery revisions in HF form.
func (s *Store) StatusUpdatesDue() ([]StatusUpdate, error) {
	values, err := s.core.StatusUpdatesDue()
	if err != nil {
		return nil, err
	}
	out := make([]StatusUpdate, 0, len(values))
	for _, value := range values {
		grant, err := fromCoreGrant(value.Grant, "")
		if err != nil {
			return nil, err
		}
		status := value.Status
		switch value.Kind {
		case bkgrants.StatusUpdateRetainedReservation:
			status = NotifierStatusReserved
		case bkgrants.StatusUpdateUsed, bkgrants.StatusUpdateUsedExpired:
			status = StatusConsumed
		}
		out = append(out, StatusUpdate{Grant: grant, Status: status, NotifierStatus: value.NotificationStatusKey()})
	}
	return out, nil
}

// ExpireDue is the expired-only compatibility view of StatusUpdatesDue.
func (s *Store) ExpireDue() ([]ExpiredGrant, error) {
	updates, err := s.StatusUpdatesDue()
	if err != nil {
		return nil, err
	}
	out := make([]ExpiredGrant, 0)
	for _, update := range updates {
		if update.Grant.Status == StatusExpired {
			out = append(out, ExpiredGrant{Grant: update.Grant, ExpiredFrom: update.Grant.ExpiredFrom, NeedsMessage: true})
		}
	}
	return out, nil
}
