// Package grants stores short-lived broker approval grants.
package grants

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/copyx"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/store"
)

const (
	defaultPendingTimeout     = 5 * time.Minute
	defaultDuration           = 5 * time.Minute
	defaultMaxDuration        = time.Hour
	defaultMaxUses            = 1
	maxMaxUses                = 25
	defaultReservationTimeout = 5 * time.Minute
)

// Grant status values.
const (
	StatusPending  Status = "pending"
	StatusActive   Status = "active"
	StatusDenied   Status = "denied"
	StatusExpired  Status = "expired"
	StatusConsumed Status = "consumed"
	StatusRevoked  Status = "revoked"
	StatusCanceled Status = "canceled"
)

var (
	ErrNotFound             = errors.New("grant not found")
	ErrInvalidDecisionToken = errors.New("invalid grant decision token")
	ErrNotPending           = errors.New("grant is not pending")
	ErrNotActive            = errors.New("grant is not active")
	ErrIdempotencyConflict  = errors.New("idempotency conflict")
)

// Status is a grant lifecycle state.
type Status string

// Options configures a Store.
type Options struct {
	PendingTimeout     time.Duration
	DefaultDuration    time.Duration
	MaxDuration        time.Duration
	ReservationTimeout time.Duration
	Now                func() time.Time
	NewID              func(int) (string, error)
}

// Request creates one pending approval grant.
type Request struct {
	Client          string
	ClientRequestID string
	Operation       string
	Target          policy.Target
	Attrs           map[string][]string
	Metadata        map[string]string
	Reason          string
	Duration        time.Duration
	PendingTimeout  time.Duration
	MaxUses         int
}

// RequestResult returns the durable grant plus the raw one-time decision token
// needed to notify approvers. The token is not part of Grant and is omitted from
// JSON so grant/status responses do not leak approval authority.
type RequestResult struct {
	Grant         Grant  `json:"grant"`
	DecisionToken string `json:"-"`
}

// Grant is one durable approval record.
type Grant struct {
	ID                     string              `json:"id"`
	DecisionTokenVerifier  string              `json:"decision_token_verifier"`
	Client                 string              `json:"client"`
	ClientRequestID        string              `json:"client_request_id,omitempty"`
	Operation              string              `json:"operation"`
	Target                 policy.Target       `json:"target"`
	Attrs                  map[string][]string `json:"attrs,omitempty"`
	Metadata               map[string]string   `json:"metadata,omitempty"`
	Reason                 string              `json:"reason"`
	Status                 Status              `json:"status"`
	CreatedAt              time.Time           `json:"created_at"`
	PendingExpiresAt       time.Time           `json:"pending_expires_at"`
	ExpiresAt              time.Time           `json:"expires_at,omitzero"`
	Duration               time.Duration       `json:"duration"`
	PendingTimeout         time.Duration       `json:"pending_timeout"`
	DecidedAt              time.Time           `json:"decided_at,omitzero"`
	DecidedBy              string              `json:"decided_by,omitempty"`
	UsedAt                 time.Time           `json:"used_at,omitzero"`
	UsedCount              int                 `json:"used_count"`
	UseRevision            int                 `json:"use_revision,omitempty"`
	ReservedCount          int                 `json:"reserved_count,omitempty"`
	ReservedAt             time.Time           `json:"reserved_at,omitzero"`
	ReservationRetained    bool                `json:"reservation_retained,omitempty"`
	ReservationRevision    int                 `json:"reservation_revision,omitempty"`
	MaxUses                int                 `json:"max_uses"`
	ExpiredFrom            Status              `json:"expired_from,omitempty"`
	Notification           *MessageRef         `json:"notification,omitempty"`
	NotificationStatus     string              `json:"notification_status,omitempty"`
	NotificationClaimedAt  time.Time           `json:"notification_claimed_at,omitzero"`
	NotificationClaimUntil time.Time           `json:"notification_claim_until,omitzero"`
	legacySchema           bool
}

type fileData struct {
	Grants []Grant `json:"grants"`
}

type compatibleValues struct {
	values []string
	legacy bool
}

func (g *Grant) UnmarshalJSON(data []byte) error {
	type grantJSON Grant
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	legacyAttrs, err := normalizeStoredValueMap(fields, "attrs")
	if err != nil {
		return fmt.Errorf("attrs: %w", err)
	}
	legacyTarget, err := normalizeStoredTarget(fields)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	var decoded grantJSON
	if err := json.Unmarshal(normalized, &decoded); err != nil {
		return err
	}
	*g = Grant(decoded)
	g.legacySchema = legacyAttrs || legacyTarget
	return nil
}

func normalizeStoredTarget(fields map[string]json.RawMessage) (bool, error) {
	raw, ok := fields["target"]
	if !ok || string(raw) == "null" {
		return false, nil
	}
	var targetFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &targetFields); err != nil {
		return false, err
	}
	legacy, err := normalizeStoredValueMap(targetFields, "Fields")
	if err != nil {
		return false, fmt.Errorf("fields: %w", err)
	}
	if !legacy {
		legacy, err = normalizeStoredValueMap(targetFields, "fields")
		if err != nil {
			return false, fmt.Errorf("fields: %w", err)
		}
	}
	return legacy, replaceJSONField(fields, "target", targetFields)
}

func normalizeStoredValueMap(fields map[string]json.RawMessage, name string) (bool, error) {
	raw, ok := fields[name]
	if !ok || string(raw) == "null" {
		return false, nil
	}
	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &encoded); err != nil {
		return false, err
	}
	legacy := false
	values := make(map[string][]string, len(encoded))
	for key, value := range encoded {
		decoded, err := decodeCompatibleValues(value)
		if err != nil {
			return false, fmt.Errorf("%s: %w", key, err)
		}
		values[key] = copyx.CanonicalStringSlice(decoded.values)
		legacy = legacy || decoded.legacy || !slices.Equal(values[key], decoded.values)
	}
	return legacy, replaceJSONField(fields, name, values)
}

func replaceJSONField(fields map[string]json.RawMessage, name string, value any) error {
	normalized, err := json.Marshal(value)
	if err != nil {
		return err
	}
	fields[name] = normalized
	return nil
}

func decodeCompatibleValues(data []byte) (compatibleValues, error) {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return compatibleValues{}, errors.New("must be a string or string array")
	}
	var scalar string
	if err := json.Unmarshal(data, &scalar); err == nil {
		return compatibleValues{values: []string{scalar}, legacy: true}, nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return compatibleValues{}, errors.New("must be a string or string array")
	}
	if len(values) == 0 {
		return compatibleValues{}, errors.New("string array must not be empty")
	}
	return compatibleValues{values: values}, nil
}

func canonicalizeLoadedGrants(grants []Grant) bool {
	changed := false
	for index := range grants {
		grant := &grants[index]
		grantChanged := grant.legacySchema
		grant.legacySchema = false
		grant.Target.Fields = copyx.CanonicalStringSliceMap(grant.Target.Fields)
		grant.Attrs = copyx.CanonicalStringSliceMap(grant.Attrs)
		grant.Metadata = copyx.StringMap(grant.Metadata)
		reservationChanged := normalizeLoadedReservation(grant)
		revisionChanged := normalizeLoadedRevisions(grant)
		changed = reservationChanged || revisionChanged || grantChanged || changed
	}
	return changed
}

func normalizeLoadedRevisions(grant *Grant) bool {
	changed := false
	if grant.UseRevision < grant.UsedCount {
		grant.UseRevision = grant.UsedCount
		changed = true
	}
	if grant.ReservedCount > 0 && grant.ReservationRevision <= 0 {
		grant.ReservationRevision = 1
		changed = true
	}
	return changed
}

func normalizeLoadedReservation(grant *Grant) bool {
	changed := grant.ReservedCount < 0
	if changed {
		grant.ReservedCount = 0
	}
	if grant.ReservedCount != 0 || (grant.ReservedAt.IsZero() && !grant.ReservationRetained) {
		return changed
	}
	grant.ReservedAt = time.Time{}
	grant.ReservationRetained = false
	return true
}

// Store owns one durable grant file.
type Store struct {
	path string
	opts Options
	mu   sync.Mutex
}

// New returns a Store.
func New(path string, opts Options) *Store {
	if opts.PendingTimeout <= 0 {
		opts.PendingTimeout = defaultPendingTimeout
	}
	if opts.DefaultDuration <= 0 {
		opts.DefaultDuration = defaultDuration
	}
	if opts.MaxDuration <= 0 {
		opts.MaxDuration = defaultMaxDuration
	}
	if opts.ReservationTimeout <= 0 {
		opts.ReservationTimeout = defaultReservationTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = randomID
	}
	return &Store{path: path, opts: opts}
}

// Request creates or returns an idempotent pending grant.
func (s *Store) Request(req Request) (RequestResult, bool, error) {
	req, err := s.normalizeRequest(req)
	if err != nil {
		return RequestResult{}, false, err
	}
	var out RequestResult
	created := false
	err = s.update(func(data *fileData) error {
		s.expireDue(data)
		if index, existing, ok := findIdempotent(data.Grants, req); ok {
			var existingErr error
			out, existingErr = s.idempotentRequest(data, index, existing, req)
			return existingErr
		}
		grant, decisionToken, err := s.newGrant(req)
		if err != nil {
			return err
		}
		data.Grants = append(data.Grants, grant)
		out = RequestResult{Grant: grant, DecisionToken: decisionToken}
		created = true
		return nil
	})
	return out, created, err
}

func (s *Store) idempotentRequest(data *fileData, index int, existing Grant, req Request) (RequestResult, error) {
	if !sameRequest(existing, req) {
		return RequestResult{}, ErrIdempotencyConflict
	}
	result := RequestResult{Grant: existing}
	if existing.Status != StatusPending || existing.Notification != nil || !existing.NotificationClaimedAt.IsZero() {
		return result, nil
	}
	refreshed, decisionToken, err := s.refreshDecisionToken(existing)
	if err != nil {
		return RequestResult{}, err
	}
	data.Grants[index] = refreshed
	return RequestResult{Grant: refreshed, DecisionToken: decisionToken}, nil
}

// Approve activates a pending grant.
func (s *Store) Approve(id string, decisionToken string, approver string) (Grant, error) {
	return s.decide(id, decisionToken, approver, StatusActive)
}

// Deny denies a pending grant.
func (s *Store) Deny(id string, decisionToken string, approver string) (Grant, error) {
	return s.decide(id, decisionToken, approver, StatusDenied)
}

// Revoke closes an active grant.
func (s *Store) Revoke(id string, approver string) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		if grant.Status != StatusActive {
			return ErrNotActive
		}
		grant.Status = StatusRevoked
		grant.DecidedAt = s.opts.Now().UTC()
		grant.DecidedBy = approver
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
}

// ReserveUse durably reserves one active grant use before execution.
func (s *Store) ReserveUse(id string) (Grant, error) {
	return s.changeUse(id, func(grant Grant) (Grant, error) {
		if !grantCanUse(grant, s.opts.Now().UTC()) {
			return Grant{}, ErrNotActive
		}
		grant.ReservedAt = s.opts.Now().UTC()
		grant.ReservationRevision++
		grant.ReservedCount++
		return grant, nil
	})
}

// RetainUse preserves a reserved use for operator review after an ambiguous
// execution result.
func (s *Store) RetainUse(id string) (Grant, error) {
	return s.changeUse(id, func(grant Grant) (Grant, error) {
		if !grantCanCommitUse(grant) {
			return Grant{}, ErrNotActive
		}
		grant.ReservationRetained = true
		if grant.ReservedAt.IsZero() {
			grant.ReservedAt = s.opts.Now().UTC()
		}
		return grant, nil
	})
}

// CommitUse turns one reservation into a used grant budget.
func (s *Store) CommitUse(id string) (Grant, error) {
	return s.changeUse(id, func(grant Grant) (Grant, error) {
		if !grantCanCommitUse(grant) {
			return Grant{}, ErrNotActive
		}
		grant.ReservedCount--
		grant.UsedCount++
		grant.UseRevision++
		grant.UsedAt = s.opts.Now().UTC()
		if grant.ReservedCount == 0 {
			grant.ReservedAt = time.Time{}
			grant.ReservationRetained = false
		} else {
			grant.ReservedAt = s.opts.Now().UTC()
		}
		if grant.UsedCount >= grant.MaxUses {
			if grant.Status != StatusRevoked {
				grant.Status = StatusConsumed
				grant.ExpiredFrom = ""
			}
		}
		return grant, nil
	})
}

// ReleaseUse releases one reserved grant use.
func (s *Store) ReleaseUse(id string) (Grant, error) {
	return s.changeUse(id, func(grant Grant) (Grant, error) {
		if grant.ReservedCount > 0 {
			grant.ReservedCount--
		}
		if grant.ReservedCount == 0 {
			grant.ReservedAt = time.Time{}
			grant.ReservationRetained = false
		} else {
			grant.ReservedAt = s.opts.Now().UTC()
		}
		return grant, nil
	})
}

// ActivePolicyGrants returns active grant overlays for policy evaluation.
func (s *Store) ActivePolicyGrants() ([]policy.Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	changed := s.expireDue(&data)
	now := s.opts.Now().UTC()
	out := make([]policy.Grant, 0, len(data.Grants))
	for _, grant := range data.Grants {
		if grantCanUse(grant, now) {
			out = append(out, grant.toPolicyGrant())
		}
	}
	if changed {
		if err := s.save(data); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Get returns one grant by id.
func (s *Store) Get(id string) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Grant{}, err
	}
	changed := s.expireDue(&data)
	_, grant, err := findGrant(data.Grants, id)
	if err != nil {
		return Grant{}, err
	}
	if changed {
		if err := s.save(data); err != nil {
			return Grant{}, err
		}
	}
	return grant, nil
}

// List returns all durable grants after expiring stale records.
func (s *Store) List() ([]Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return nil, err
	}
	changed := s.expireDue(&data)
	out := make([]Grant, len(data.Grants))
	copy(out, data.Grants)
	if changed {
		if err := s.save(data); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ListForClient returns all durable grants for one broker client.
func (s *Store) ListForClient(client string) ([]Grant, error) {
	grants, err := s.List()
	if err != nil {
		return nil, err
	}
	out := make([]Grant, 0, len(grants))
	for _, grant := range grants {
		if grant.Client == client {
			out = append(out, grant)
		}
	}
	return out, nil
}

func (s *Store) decide(id string, token string, approver string, status Status) (Grant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return Grant{}, err
	}
	index, grant, err := findGrant(data.Grants, id)
	if err != nil {
		return Grant{}, err
	}
	if !decisionTokenMatches(grant.DecisionTokenVerifier, token) {
		return Grant{}, ErrInvalidDecisionToken
	}
	return s.decideFound(&data, index, grant, approver, status)
}

func decisionTokenVerifier(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func decisionTokenMatches(storedVerifier string, presented string) bool {
	if storedVerifier == "" || presented == "" {
		return false
	}
	expectedVerifier := decisionTokenVerifier(presented)
	storedHash := sha256.Sum256([]byte(storedVerifier))
	presentedHash := sha256.Sum256([]byte(expectedVerifier))
	return subtle.ConstantTimeCompare(storedHash[:], presentedHash[:]) == 1
}

func (s *Store) decideFound(data *fileData, index int, grant Grant, approver string, status Status) (Grant, error) {
	now := s.opts.Now().UTC()
	if grant.Status != StatusPending {
		return Grant{}, ErrNotPending
	}
	if !now.Before(grant.PendingExpiresAt) {
		return s.expireLateDecision(data, index, grant)
	}
	grant.Status = status
	grant.DecidedAt = now
	grant.DecidedBy = approver
	if status == StatusActive {
		grant.ExpiresAt = now.Add(s.durationFromGrant(grant))
	}
	return s.saveDecidedGrant(data, index, grant)
}

func (s *Store) expireLateDecision(data *fileData, index int, grant Grant) (Grant, error) {
	grant.ExpiredFrom = grant.Status
	grant.Status = StatusExpired
	grant.DecidedAt = s.opts.Now().UTC()
	data.Grants[index] = grant
	if err := s.save(*data); err != nil {
		return Grant{}, err
	}
	return grant, ErrNotPending
}

func (s *Store) saveDecidedGrant(data *fileData, index int, grant Grant) (Grant, error) {
	data.Grants[index] = grant
	if err := s.save(*data); err != nil {
		return Grant{}, err
	}
	return grant, nil
}

func (s *Store) changeUse(id string, mutate func(Grant) (Grant, error)) (Grant, error) {
	var out Grant
	err := s.update(func(data *fileData) error {
		index, grant, err := findGrant(data.Grants, id)
		if err != nil {
			return err
		}
		updated, err := mutate(grant)
		if err != nil {
			return err
		}
		data.Grants[index] = updated
		out = updated
		return nil
	})
	return out, err
}

func (s *Store) normalizeRequest(req Request) (Request, error) {
	normalized, err := normalizeRequestValues(req)
	if err != nil {
		return Request{}, err
	}
	return s.normalizeRequestBounds(normalized)
}

func normalizeRequestValues(req Request) (Request, error) {
	if req.Client == "" || req.Operation == "" || req.Target.Kind == "" {
		return Request{}, errors.New("client, operation, and target are required")
	}
	if req.Reason == "" {
		return Request{}, errors.New("grant reason is required")
	}
	if err := validateValueMap("target field", req.Target.Fields); err != nil {
		return Request{}, err
	}
	if err := validateValueMap("attr", req.Attrs); err != nil {
		return Request{}, err
	}
	if err := validateMetadata(req.Metadata); err != nil {
		return Request{}, err
	}
	req.Target.Fields = copyx.CanonicalStringSliceMap(req.Target.Fields)
	req.Attrs = copyx.CanonicalStringSliceMap(req.Attrs)
	req.Metadata = copyx.StringMap(req.Metadata)
	return req, nil
}

func validateValueMap(kind string, values map[string][]string) error {
	for name, list := range values {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s name is required", kind)
		}
		if len(list) == 0 {
			return fmt.Errorf("%s %q values must not be empty", kind, name)
		}
		for _, value := range list {
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s %q contains an empty value", kind, name)
			}
		}
	}
	return nil
}

func (s *Store) normalizeRequestBounds(req Request) (Request, error) {
	if req.Duration <= 0 {
		req.Duration = s.opts.DefaultDuration
	}
	if req.Duration > s.opts.MaxDuration {
		return Request{}, errors.New("grant duration exceeds maximum")
	}
	if req.PendingTimeout <= 0 {
		req.PendingTimeout = s.opts.PendingTimeout
	}
	if req.MaxUses <= 0 {
		req.MaxUses = defaultMaxUses
	}
	if req.MaxUses > maxMaxUses {
		return Request{}, errors.New("grant max uses exceeds maximum")
	}
	return req, nil
}

func (s *Store) newGrant(req Request) (Grant, string, error) {
	id, err := s.opts.NewID(16)
	if err != nil {
		return Grant{}, "", err
	}
	token, err := s.opts.NewID(12)
	if err != nil {
		return Grant{}, "", err
	}
	now := s.opts.Now().UTC()
	return Grant{
		ID:                    id,
		DecisionTokenVerifier: decisionTokenVerifier(token),
		Client:                req.Client,
		ClientRequestID:       req.ClientRequestID,
		Operation:             req.Operation,
		Target:                req.Target,
		Attrs:                 req.Attrs,
		Metadata:              req.Metadata,
		Reason:                req.Reason,
		Status:                StatusPending,
		CreatedAt:             now,
		PendingExpiresAt:      now.Add(req.PendingTimeout),
		Duration:              req.Duration,
		PendingTimeout:        req.PendingTimeout,
		MaxUses:               req.MaxUses,
	}, token, nil
}

func (s *Store) refreshDecisionToken(grant Grant) (Grant, string, error) {
	token, err := s.opts.NewID(12)
	if err != nil {
		return Grant{}, "", err
	}
	grant.DecisionTokenVerifier = decisionTokenVerifier(token)
	return grant, token, nil
}

func (s *Store) durationFromGrant(grant Grant) time.Duration {
	duration := grant.Duration
	if duration <= 0 {
		duration = grant.ExpiresAt.Sub(grant.CreatedAt)
	}
	if duration <= 0 || duration > s.opts.MaxDuration {
		return s.opts.DefaultDuration
	}
	return duration
}

func (s *Store) update(mutator func(*fileData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return err
	}
	changed := s.prepareLifecycle(&data)
	if err := mutator(&data); err != nil {
		if changed {
			return errors.Join(err, s.save(data))
		}
		return err
	}
	return s.save(data)
}

func (s *Store) load() (fileData, error) {
	var data fileData
	if err := store.ReadJSON(s.path, &data); err != nil {
		return fileData{}, err
	}
	if canonicalizeLoadedGrants(data.Grants) {
		if err := s.save(data); err != nil {
			return fileData{}, err
		}
	}
	return data, nil
}

func (s *Store) save(data fileData) error {
	return store.WriteJSONAtomic(s.path, data, 0o600)
}

func (s *Store) expireDue(data *fileData) bool {
	now := s.opts.Now().UTC()
	changed := false
	for index, grant := range data.Grants {
		switch {
		case grant.Status == StatusPending && !now.Before(grant.PendingExpiresAt):
			grant.ExpiredFrom = grant.Status
			grant.Status = StatusExpired
			grant.DecidedAt = now
		case grant.Status == StatusActive && !now.Before(grant.ExpiresAt):
			grant.ExpiredFrom = grant.Status
			grant.Status = StatusExpired
		default:
			continue
		}
		data.Grants[index] = grant
		changed = true
	}
	return changed
}

func (s *Store) prepareLifecycle(data *fileData) bool {
	expired := s.expireDue(data)
	retained := s.retainStaleReservations(data)
	return expired || retained
}

func (s *Store) retainStaleReservations(data *fileData) bool {
	now := s.opts.Now().UTC()
	changed := false
	for index, grant := range data.Grants {
		if !reservationIsStale(grant, now, s.opts.ReservationTimeout) {
			continue
		}
		grant.ReservationRetained = true
		if grant.ReservedAt.IsZero() {
			grant.ReservedAt = now
		}
		data.Grants[index] = grant
		changed = true
	}
	return changed
}

func reservationIsStale(grant Grant, now time.Time, timeout time.Duration) bool {
	if grant.ReservationRetained || grant.ReservedCount <= 0 ||
		!reservationCanSettle(grant.Status) {
		return false
	}
	return grant.ReservedAt.IsZero() || !now.Before(grant.ReservedAt.Add(timeout))
}

func grantCanUse(grant Grant, now time.Time) bool {
	return grant.Status == StatusActive &&
		!grant.ReservationRetained &&
		now.Before(grant.ExpiresAt) &&
		grant.UsedCount+grant.ReservedCount < grant.MaxUses
}

func grantCanCommitUse(grant Grant) bool {
	return grant.ReservedCount > 0 && reservationCanSettle(grant.Status)
}

func reservationCanSettle(status Status) bool {
	return status == StatusActive || status == StatusExpired || status == StatusRevoked
}

func (g Grant) toPolicyGrant() policy.Grant {
	return policy.Grant{
		ID:        g.ID,
		Client:    g.Client,
		Operation: g.Operation,
		Target: policy.Target{
			Kind:   g.Target.Kind,
			Fields: copyx.StringSliceMap(g.Target.Fields),
		},
		Attrs:     copyx.StringSliceMap(g.Attrs),
		ExpiresAt: g.ExpiresAt,
		UsesLeft:  g.MaxUses - g.UsedCount - g.ReservedCount,
	}
}

func findGrant(grants []Grant, id string) (int, Grant, error) {
	for index, grant := range grants {
		if grant.ID == id {
			return index, grant, nil
		}
	}
	return -1, Grant{}, ErrNotFound
}

func findIdempotent(grants []Grant, req Request) (int, Grant, bool) {
	if req.ClientRequestID == "" {
		return -1, Grant{}, false
	}
	for index, grant := range grants {
		if grant.Client == req.Client && grant.ClientRequestID == req.ClientRequestID && grant.Status != StatusCanceled {
			return index, grant, true
		}
	}
	return -1, Grant{}, false
}

func sameRequest(grant Grant, req Request) bool {
	return grant.Operation == req.Operation &&
		targetEqual(grant.Target, req.Target) &&
		mapsEqual(grant.Attrs, req.Attrs) &&
		stringMapsEqual(grant.Metadata, req.Metadata) &&
		grant.Reason == req.Reason &&
		grant.MaxUses == req.MaxUses &&
		grant.Duration == req.Duration &&
		grant.PendingTimeout == req.PendingTimeout
}

func targetEqual(left policy.Target, right policy.Target) bool {
	return left.Kind == right.Kind && mapsEqual(left.Fields, right.Fields)
}

func mapsEqual(left, right map[string][]string) bool {
	return copyx.StringSliceMapsEqual(left, right)
}

func randomID(bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// mutate4go-manifest-begin
// {"version":1,"tested_at":"2026-07-09T23:00:20+08:00","module_hash":"ffa5913b7e9b9135b18a916c74b9d9ba9725a95f1dfacdf4b2bb85715cd54550","functions":[{"id":"func/New","name":"New","line":116,"end_line":133,"hash":"358b71e75d1d6d7a3880cd84032874b58a04a1d485f12a5934a8a33052f6e15d"},{"id":"func/Store.Request","name":"Store.Request","line":136,"end_line":170,"hash":"94828c0023428d22207028253214781f0e07197cf7af4fc63e1177ef008810c0"},{"id":"func/Store.Approve","name":"Store.Approve","line":173,"end_line":175,"hash":"a708045214fbeb6b3ac4ea45c0768cd900abd60128881b3a2a7520a4829ca9cd"},{"id":"func/Store.Deny","name":"Store.Deny","line":178,"end_line":180,"hash":"adeeea8b8c8926b4408c1fb35c99d45471a4afcfe9313f5700771f5c959b34c6"},{"id":"func/Store.Revoke","name":"Store.Revoke","line":183,"end_line":201,"hash":"47bf3ef1266e24022df2fb3dc6715c23aa00f49f5e12480a0996668905fa1e6d"},{"id":"func/Store.ReserveUse","name":"Store.ReserveUse","line":204,"end_line":212,"hash":"1267a157a4fa7f51453c495cd519235e55e5eb0432fc5b5e03f43afb8ef54bdd"},{"id":"func/Store.CommitUse","name":"Store.CommitUse","line":215,"end_line":228,"hash":"76869880bed6ab7e629bc6feaa3a7882d549a69b3a28efe064f42ce0edb52344"},{"id":"func/Store.ReleaseUse","name":"Store.ReleaseUse","line":231,"end_line":238,"hash":"5619e6ea8004276398273953f406c4b181ec9bcc497278fc27d04a48a02ecc3a"},{"id":"func/Store.ActivePolicyGrants","name":"Store.ActivePolicyGrants","line":241,"end_line":262,"hash":"88e08a665d56703d47c17058b0719afeafb495a74380446dcf7d3a9826a6da92"},{"id":"func/Store.Get","name":"Store.Get","line":265,"end_line":283,"hash":"fe2baf289943a1b196619330b047a9625322d07da12dee86e1f5638cd7a03144"},{"id":"func/Store.List","name":"Store.List","line":286,"end_line":302,"hash":"c02f0d7da3db0b468bb42e1431f0a604fd55e7494aa2e3e0b97ae6b89acb2b01"},{"id":"func/Store.ListForClient","name":"Store.ListForClient","line":305,"end_line":317,"hash":"4f1ae2824d6ae1b2a80fafeb844b87c0fcc6c21db5836e5db010b9e4f7f5df55"},{"id":"func/Store.decide","name":"Store.decide","line":319,"end_line":334,"hash":"2c5bf7a06bd8f87cf3f8cddbf10749eb0b5993bcb04660a37a1f07b94cad7abe"},{"id":"func/decisionTokenVerifier","name":"decisionTokenVerifier","line":336,"end_line":339,"hash":"5af04fa6107ef97ef5c15a945113598580ae311abdd0127e6b52c59c9fe6e635"},{"id":"func/decisionTokenMatches","name":"decisionTokenMatches","line":341,"end_line":349,"hash":"fe22f72b58b6e15c80aacb220576484eba16ac6d85f0e2d33b0dd7a36a84bdcc"},{"id":"func/Store.decideFound","name":"Store.decideFound","line":351,"end_line":366,"hash":"643d286d9fb9253d6d8fe289e0c96c92e7cb6da4acde710ba7803df065eb2b8d"},{"id":"func/Store.expireLateDecision","name":"Store.expireLateDecision","line":368,"end_line":375,"hash":"c11ac8dcdf23025399ff22851281b0cc4eaa550aaa91ceaab4ed09aeac8e9831"},{"id":"func/Store.saveDecidedGrant","name":"Store.saveDecidedGrant","line":377,"end_line":383,"hash":"f5627efcb197cd02aabe17fcb6cd64d0ed982f7af82f789af055f610b01b3b9d"},{"id":"func/Store.changeUse","name":"Store.changeUse","line":385,"end_line":401,"hash":"66329c22ae3e00e5f3822666b5a88786f5c087671f0e8517f1dd9116d5812b43"},{"id":"func/Store.normalizeRequest","name":"Store.normalizeRequest","line":403,"end_line":417,"hash":"23397407034ba979ee2a6acf3f35d4d3df6c2c5fcc60759ea771f7bde6e215c8"},{"id":"func/Store.normalizeRequestBounds","name":"Store.normalizeRequestBounds","line":419,"end_line":436,"hash":"fd2ee52a812ebe944267ebd9597965bf82dbf867180ef46a1382d7611f0a1610"},{"id":"func/Store.newGrant","name":"Store.newGrant","line":438,"end_line":464,"hash":"1a1a7509b69cff6207163c1e8b931ed6e03f98dc46cc1af91ae1ff6448020037"},{"id":"func/Store.refreshDecisionToken","name":"Store.refreshDecisionToken","line":466,"end_line":473,"hash":"3799d936d7c85ed25a094008743d22518fb7ff35590b167077177f8a0aac5467"},{"id":"func/Store.durationFromGrant","name":"Store.durationFromGrant","line":475,"end_line":484,"hash":"1a506f93d55575afb168418eb27594811724f770711c375d5485ba3c2decd8de"},{"id":"func/Store.update","name":"Store.update","line":486,"end_line":497,"hash":"4f8593ac0c04cdac0df168b67eb413d0d029503562d515ee9c9d0c57e36f567d"},{"id":"func/Store.load","name":"Store.load","line":499,"end_line":505,"hash":"987c239bf1410a89de9d78c62f42e9a10aa97ccc0d603def2e2b4405c3478a07"},{"id":"func/Store.save","name":"Store.save","line":507,"end_line":509,"hash":"38d911cb2a19db23af02633273f20900c75441d10fb95fac3d53afb1555af603"},{"id":"func/Store.expireDue","name":"Store.expireDue","line":511,"end_line":527,"hash":"d4af1d14d2636338ff53538f73d56b9f2ac34967d63c30f0f241722b4dfaf835"},{"id":"func/grantCanUse","name":"grantCanUse","line":529,"end_line":533,"hash":"cbbf0cdb01fbf9613ae8d1cf272556c4216728ee192ea392e99b41c7ae345479"},{"id":"func/Grant.toPolicyGrant","name":"Grant.toPolicyGrant","line":535,"end_line":545,"hash":"a9a8d71c0d2d69a419e995799d50b8e9c0e060cb2dade58a7d94b162690ca14e"},{"id":"func/findGrant","name":"findGrant","line":547,"end_line":554,"hash":"80508b0495a632e35244ba37b6e1049487c60ba0282c02375167907e76935fb5"},{"id":"func/findIdempotent","name":"findIdempotent","line":556,"end_line":566,"hash":"6470797a3c77f90d1fc348277f4ac4a95f723ca1e3bbae87c5a8d6515bdcf83e"},{"id":"func/sameRequest","name":"sameRequest","line":568,"end_line":576,"hash":"c4dc0467af76a4325db4e9a168ad9b5c428989c1df54a7206c124d2e2af5ea11"},{"id":"func/targetEqual","name":"targetEqual","line":578,"end_line":580,"hash":"810011ca9d9cab99e1024b2af13f5006c487f3b94551c43517620f8c61089710"},{"id":"func/mapsEqual","name":"mapsEqual","line":582,"end_line":586,"hash":"4a16c06aa272e4e24dec8e0ae7e608c279e2568818742226ee2bcc5a2a080ae3"},{"id":"func/randomID","name":"randomID","line":588,"end_line":594,"hash":"3187089d24ba5ad550c1fdd80e9afcf66c69cc47e21c41890f8be53a41629001"}]}
// mutate4go-manifest-end
