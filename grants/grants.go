// Package grants stores short-lived broker approval grants.
package grants

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/copyx"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/store"
)

const (
	defaultPendingTimeout = 5 * time.Minute
	defaultDuration       = 5 * time.Minute
	defaultMaxDuration    = time.Hour
	defaultMaxUses        = 1
	maxMaxUses            = 25
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
	PendingTimeout  time.Duration
	DefaultDuration time.Duration
	MaxDuration     time.Duration
	Now             func() time.Time
	NewID           func(int) (string, error)
}

// Request creates one pending approval grant.
type Request struct {
	Client          string
	ClientRequestID string
	Operation       string
	Target          policy.Target
	Attrs           map[string]string
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
	ID                    string            `json:"id"`
	DecisionTokenVerifier string            `json:"decision_token_verifier"`
	Client                string            `json:"client"`
	ClientRequestID       string            `json:"client_request_id,omitempty"`
	Operation             string            `json:"operation"`
	Target                policy.Target     `json:"target"`
	Attrs                 map[string]string `json:"attrs,omitempty"`
	Reason                string            `json:"reason"`
	Status                Status            `json:"status"`
	CreatedAt             time.Time         `json:"created_at"`
	PendingExpiresAt      time.Time         `json:"pending_expires_at"`
	ExpiresAt             time.Time         `json:"expires_at,omitzero"`
	Duration              time.Duration     `json:"duration"`
	PendingTimeout        time.Duration     `json:"pending_timeout"`
	DecidedAt             time.Time         `json:"decided_at,omitzero"`
	DecidedBy             string            `json:"decided_by,omitempty"`
	UsedAt                time.Time         `json:"used_at,omitzero"`
	UsedCount             int               `json:"used_count"`
	ReservedCount         int               `json:"reserved_count,omitempty"`
	MaxUses               int               `json:"max_uses"`
}

type fileData struct {
	Grants []Grant `json:"grants"`
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
			if !sameRequest(existing, req) {
				return ErrIdempotencyConflict
			}
			out = RequestResult{Grant: existing}
			if existing.Status == StatusPending {
				refreshed, decisionToken, err := s.refreshDecisionToken(existing)
				if err != nil {
					return err
				}
				data.Grants[index] = refreshed
				out = RequestResult{Grant: refreshed, DecisionToken: decisionToken}
			}
			return nil
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
		grant.ReservedCount++
		return grant, nil
	})
}

// CommitUse turns one reservation into a used grant budget.
func (s *Store) CommitUse(id string) (Grant, error) {
	return s.changeUse(id, func(grant Grant) (Grant, error) {
		if grant.ReservedCount <= 0 {
			return Grant{}, ErrNotActive
		}
		grant.ReservedCount--
		grant.UsedCount++
		grant.UsedAt = s.opts.Now().UTC()
		if grant.UsedCount >= grant.MaxUses {
			grant.Status = StatusConsumed
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
	grant.Status = StatusExpired
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
	if req.Client == "" || req.Operation == "" || req.Target.Kind == "" {
		return Request{}, errors.New("client, operation, and target are required")
	}
	if req.Reason == "" {
		return Request{}, errors.New("grant reason is required")
	}
	normalized, err := s.normalizeRequestBounds(req)
	if err != nil {
		return Request{}, err
	}
	normalized.Target.Fields = copyx.StringMap(normalized.Target.Fields)
	normalized.Attrs = copyx.StringMap(normalized.Attrs)
	return normalized, nil
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
	if err := mutator(&data); err != nil {
		return err
	}
	return s.save(data)
}

func (s *Store) load() (fileData, error) {
	var data fileData
	if err := store.ReadJSON(s.path, &data); err != nil {
		return fileData{}, err
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
			grant.Status = StatusExpired
		case grant.Status == StatusActive && !now.Before(grant.ExpiresAt):
			grant.Status = StatusExpired
		default:
			continue
		}
		data.Grants[index] = grant
		changed = true
	}
	return changed
}

func grantCanUse(grant Grant, now time.Time) bool {
	return grant.Status == StatusActive &&
		now.Before(grant.ExpiresAt) &&
		grant.UsedCount+grant.ReservedCount < grant.MaxUses
}

func (g Grant) toPolicyGrant() policy.Grant {
	return policy.Grant{
		ID:        g.ID,
		Client:    g.Client,
		Operation: g.Operation,
		Target:    g.Target,
		Attrs:     copyx.StringMap(g.Attrs),
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
		grant.Reason == req.Reason &&
		grant.MaxUses == req.MaxUses &&
		grant.Duration == req.Duration &&
		grant.PendingTimeout == req.PendingTimeout
}

func targetEqual(left policy.Target, right policy.Target) bool {
	return left.Kind == right.Kind && mapsEqual(left.Fields, right.Fields)
}

func mapsEqual(left, right map[string]string) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && string(leftJSON) == string(rightJSON)
}

func randomID(bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
