// Package grants stores short-lived broker approval grants.
package grants

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

	"github.com/osolmaz/brokerkit/internal/copyx"
	"github.com/osolmaz/brokerkit/internal/strictjson"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
	"github.com/osolmaz/brokerkit/store"
)

const (
	grantFileVersion          = 1
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
	ErrUnsupportedState     = errors.New("unsupported grant state")
)

// Status is a grant lifecycle state.
type Status string

// Options configures a Store.
type Options struct {
	PendingTimeout     time.Duration
	DefaultDuration    time.Duration
	MaxDuration        time.Duration
	ReservationTimeout time.Duration
	MaxEvents          int
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

// ImmutablePlan is the provider-neutral envelope committed with a grant.
type ImmutablePlan struct {
	Digest     string
	SchemaName string
	Canonical  []byte
	CreatedAt  time.Time
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
	Revision               int64               `json:"revision"`
	CreatedAt              time.Time           `json:"created_at"`
	PendingExpiresAt       time.Time           `json:"pending_expires_at"`
	ExpiresAt              time.Time           `json:"expires_at,omitzero"`
	Duration               time.Duration       `json:"duration"`
	RequestedDuration      time.Duration       `json:"requested_duration"`
	PendingTimeout         time.Duration       `json:"pending_timeout"`
	DecidedAt              time.Time           `json:"decided_at,omitzero"`
	DecidedBy              string              `json:"decided_by,omitempty"`
	DecidedOnBehalfOf      string              `json:"decided_on_behalf_of,omitempty"`
	DecisionReason         string              `json:"decision_reason,omitempty"`
	UsedAt                 time.Time           `json:"used_at,omitzero"`
	UsedCount              int                 `json:"used_count"`
	UseRevision            int                 `json:"use_revision,omitempty"`
	ReservedCount          int                 `json:"reserved_count,omitempty"`
	ReservedAt             time.Time           `json:"reserved_at,omitzero"`
	ReservationRetained    bool                `json:"reservation_retained,omitempty"`
	ReservationRevision    int                 `json:"reservation_revision,omitempty"`
	MaxUses                int                 `json:"max_uses"`
	RequestedMaxUses       int                 `json:"requested_max_uses"`
	ExpiredFrom            Status              `json:"expired_from,omitempty"`
	Notification           *MessageRef         `json:"notification,omitempty"`
	NotificationStatus     string              `json:"notification_status,omitempty"`
	NotificationClaimedAt  time.Time           `json:"notification_claimed_at,omitzero"`
	NotificationClaimUntil time.Time           `json:"notification_claim_until,omitzero"`
	// NotificationDeliveryUnresolved records an ambiguous send attempt until
	// the current claim is completed or reclaimed.
	NotificationDeliveryUnresolved bool `json:"notification_delivery_unresolved,omitempty"`
}

type fileData struct {
	Version         int                    `json:"version"`
	Grants          []Grant                `json:"grants"`
	Events          []lifecycleEventRecord `json:"events,omitempty"`
	NextEvent       uint64                 `json:"next_event,omitempty"`
	DecisionRecords []decisionRecord       `json:"decision_records,omitempty"`
}

// Store owns one durable grant file.
type Store struct {
	path           string
	database       *state.Database
	loadedSnapshot *state.GrantSnapshot
	opts           Options
	mu             sync.Mutex
	eventMu        sync.Mutex
	eventSignal    chan struct{}
}

// New returns a Store.
func New(path string, opts Options) *Store {
	return newStore(path, nil, opts)
}

// NewDatabase returns a Store backed by BrokerKit's transactional SQLite
// state. The database owner remains responsible for closing it.
func NewDatabase(database *state.Database, opts Options) *Store {
	return newStore("", database, opts)
}

// SupportsPlanTransactions reports whether immutable plans can commit with
// grant creation in one database transaction.
func (s *Store) SupportsPlanTransactions() bool { return s != nil && s.database != nil }

func newStore(path string, database *state.Database, opts Options) *Store {
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
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = defaultMaxEvents
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.NewID == nil {
		opts.NewID = randomID
	}
	return &Store{path: path, database: database, opts: opts, eventSignal: make(chan struct{})}
}

// Request creates or returns an idempotent pending grant.
func (s *Store) Request(req Request) (RequestResult, bool, error) {
	return s.request(req, nil)
}

// RequestWithPlan atomically creates or replays a SQLite-backed grant and its
// immutable provider plan.
func (s *Store) RequestWithPlan(req Request, plan ImmutablePlan) (RequestResult, bool, error) {
	if s == nil || s.database == nil {
		return RequestResult{}, false, errors.New("SQLite grant store is required")
	}
	digest, err := metadataPlanDigest(req.Metadata)
	if err != nil || digest == "" || digest != plan.Digest || plan.CreatedAt.IsZero() {
		return RequestResult{}, false, errors.New("grant immutable plan is invalid")
	}
	record := &state.PlanRecord{Digest: plan.Digest, SchemaName: plan.SchemaName, Canonical: bytes.Clone(plan.Canonical), CreatedAt: plan.CreatedAt}
	return s.request(req, record)
}

func (s *Store) request(req Request, plan *state.PlanRecord) (RequestResult, bool, error) {
	req, err := s.normalizeRequest(req)
	if err != nil {
		return RequestResult{}, false, err
	}
	var out RequestResult
	created := false
	err = s.updateWithPlan(plan, func(data *fileData) error {
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
	if err == nil && out.Grant.ID != "" {
		out.Grant, err = s.Get(out.Grant.ID)
	}
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
	if err == nil && out.ID != "" {
		out, err = s.Get(out.ID)
	}
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
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	changed := s.expireDue(&data)
	changed = s.reconcileLifecycle(&data, before) || changed
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
		s.signalNewEvents(eventSequence, data.NextEvent)
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
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	changed := s.expireDue(&data)
	changed = s.reconcileLifecycle(&data, before) || changed
	_, grant, err := findGrant(data.Grants, id)
	if err != nil {
		return Grant{}, err
	}
	if changed {
		if err := s.save(data); err != nil {
			return Grant{}, err
		}
		s.signalNewEvents(eventSequence, data.NextEvent)
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
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	changed := s.expireDue(&data)
	changed = s.reconcileLifecycle(&data, before) || changed
	out := make([]Grant, len(data.Grants))
	copy(out, data.Grants)
	if changed {
		if err := s.save(data); err != nil {
			return nil, err
		}
		s.signalNewEvents(eventSequence, data.NextEvent)
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
	if err == nil && out.ID != "" {
		out, err = s.Get(out.ID)
	}
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
		RequestedDuration:     req.Duration,
		PendingTimeout:        req.PendingTimeout,
		MaxUses:               req.MaxUses,
		RequestedMaxUses:      req.MaxUses,
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
	return s.updateWithPlan(nil, mutator)
}

func (s *Store) updateWithPlan(plan *state.PlanRecord, mutator func(*fileData) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := s.load()
	if err != nil {
		return err
	}
	before := grantSnapshots(data.Grants)
	eventSequence := data.NextEvent
	changed := s.prepareLifecycle(&data)
	if err := mutator(&data); err != nil {
		changed = s.reconcileLifecycle(&data, before) || changed
		if changed {
			saveErr := s.save(data)
			if saveErr == nil {
				s.signalNewEvents(eventSequence, data.NextEvent)
			}
			return errors.Join(err, saveErr)
		}
		return err
	}
	s.reconcileLifecycle(&data, before)
	if err := s.saveWithPlan(data, plan); err != nil {
		return err
	}
	s.signalNewEvents(eventSequence, data.NextEvent)
	return nil
}

func (s *Store) load() (fileData, error) {
	if s.database != nil {
		snapshot, err := s.database.GrantSnapshot(context.Background())
		if err != nil {
			return fileData{}, err
		}
		s.loadedSnapshot = &snapshot
		data, err := fileDataFromSQLite(snapshot)
		if err != nil {
			return fileData{}, err
		}
		if err := validateLoadedGrants(data.Grants); err != nil {
			return fileData{}, err
		}
		if err := normalizeLoadedEvents(&data); err != nil {
			return fileData{}, err
		}
		return data, nil
	}
	data, err := s.readState()
	if err != nil {
		return fileData{}, err
	}
	if err := validateLoadedGrants(data.Grants); err != nil {
		return fileData{}, err
	}
	if err := normalizeLoadedEvents(&data); err != nil {
		return fileData{}, err
	}
	return data, nil
}

func (s *Store) save(data fileData) error {
	return s.saveWithPlan(data, nil)
}

func (s *Store) saveWithPlan(data fileData, plan *state.PlanRecord) error {
	if s.database != nil {
		if s.loadedSnapshot == nil {
			return errors.New("grant SQLite snapshot is unavailable")
		}
		before := *s.loadedSnapshot
		after, err := fileDataToSQLite(data, before.Outbox, s.opts.Now().UTC())
		if err != nil {
			return err
		}
		s.loadedSnapshot = nil
		if plan != nil {
			return s.database.SaveGrantSnapshotWithPlan(context.Background(), before, after, *plan)
		}
		return s.database.SaveGrantSnapshot(context.Background(), before, after)
	}
	if plan != nil {
		return errors.New("immutable plan transactions require SQLite")
	}
	data.Version = grantFileVersion
	return store.WriteJSONAtomic(s.path, data, 0o600)
}

func (s *Store) readState() (fileData, error) {
	raw, err := os.ReadFile(s.path) // #nosec G304 -- the state path is operator configured.
	if errors.Is(err, os.ErrNotExist) || (err == nil && len(bytes.TrimSpace(raw)) == 0) {
		return fileData{Version: grantFileVersion, NextEvent: 1}, nil
	}
	if err != nil {
		return fileData{}, err
	}
	return decodeState(raw)
}

func decodeState(raw []byte) (fileData, error) {
	if err := strictjson.RejectDuplicateKeys(raw); err != nil {
		return fileData{}, fmt.Errorf("%w: %w", ErrUnsupportedState, err)
	}
	var data fileData
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&data); err != nil {
		return fileData{}, fmt.Errorf("%w: %w", ErrUnsupportedState, err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fileData{}, ErrUnsupportedState
	}
	if data.Version != grantFileVersion {
		return fileData{}, fmt.Errorf("%w: version %d", ErrUnsupportedState, data.Version)
	}
	return data, nil
}

func validateLoadedGrants(items []Grant) error {
	seen := make(map[string]bool, len(items))
	for _, grant := range items {
		if !validGrantIdentity(grant, seen) || !validGrantLifecycle(grant) || !validGrantUsage(grant) || !validGrantReservation(grant) {
			return ErrUnsupportedState
		}
		seen[grant.ID] = true
		if err := validateLoadedGrantMaps(grant); err != nil {
			return err
		}
	}
	return nil
}

func validateLoadedGrantMaps(grant Grant) error {
	if err := validateValueMap("target field", grant.Target.Fields); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupportedState, err)
	}
	if err := validateValueMap("attr", grant.Attrs); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupportedState, err)
	}
	if err := validateMetadata(grant.Metadata); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupportedState, err)
	}
	return nil
}

func validGrantIdentity(grant Grant, seen map[string]bool) bool {
	return grant.ID != "" && !seen[grant.ID] && grant.DecisionTokenVerifier != "" && grant.Client != "" &&
		grant.Operation != "" && grant.Target.Kind != "" && grant.Reason != ""
}

func validGrantLifecycle(grant Grant) bool {
	return validStoredStatus(grant.Status) && grant.Revision >= 1 && !grant.CreatedAt.IsZero() &&
		!grant.PendingExpiresAt.IsZero() && grant.Duration > 0 && grant.RequestedDuration > 0 && grant.PendingTimeout > 0
}

func validGrantUsage(grant Grant) bool {
	return grant.MaxUses > 0 && grant.RequestedMaxUses > 0 && grant.UsedCount >= 0 &&
		grant.ReservedCount >= 0 && grant.UseRevision >= grant.UsedCount
}

func validGrantReservation(grant Grant) bool {
	return grant.ReservedCount == 0 || (!grant.ReservedAt.IsZero() && grant.ReservationRevision >= 1)
}

func validStoredStatus(status Status) bool {
	switch status {
	case StatusPending, StatusActive, StatusDenied, StatusExpired, StatusConsumed, StatusRevoked, StatusCanceled:
		return true
	default:
		return false
	}
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
			grant.NotificationDeliveryUnresolved = false
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
