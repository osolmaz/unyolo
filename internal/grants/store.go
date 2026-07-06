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
	DefaultDuration = 15 * time.Minute
	// MaxDuration is the hard cap for one approved grant.
	MaxDuration = time.Hour
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
	PendingTimeout  time.Duration
	DefaultDuration time.Duration
	MaxDuration     time.Duration
	Now             func() time.Time
}

// Request is one requested grant.
type Request struct {
	Client            string
	Operation         string
	Target            string
	Ref               string
	Reason            string
	RequestedDuration time.Duration
}

// Grant is one persisted grant request or approval.
type Grant struct {
	ID               string    `json:"id"`
	DecisionToken    string    `json:"decision_token"`
	Client           string    `json:"client"`
	Operation        string    `json:"operation"`
	Target           string    `json:"target"`
	Ref              string    `json:"ref"`
	Reason           string    `json:"reason"`
	RequestedMinutes int       `json:"requested_minutes"`
	Status           Status    `json:"status"`
	CreatedAt        time.Time `json:"created_at"`
	PendingExpiresAt time.Time `json:"pending_expires_at"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	DecidedAt        time.Time `json:"decided_at,omitempty"`
	DecidedBy        string    `json:"decided_by,omitempty"`
	UsedAt           time.Time `json:"used_at,omitempty"`
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
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Store{path: path, opts: opts}
}

// Request creates a pending grant.
func (s *Store) Request(req Request) (Grant, error) {
	duration, minutes, err := s.requestDuration(req.RequestedDuration)
	if err != nil {
		return Grant{}, err
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		return Grant{}, errors.New("grant reason is required")
	}
	if len(reason) > 512 {
		return Grant{}, errors.New("grant reason is longer than 512 bytes")
	}
	id, err := randomID(16)
	if err != nil {
		return Grant{}, err
	}
	decisionToken, err := randomID(8)
	if err != nil {
		return Grant{}, err
	}
	now := s.opts.Now().UTC()
	grant := Grant{
		ID:               id,
		DecisionToken:    decisionToken,
		Client:           req.Client,
		Operation:        req.Operation,
		Target:           req.Target,
		Ref:              req.Ref,
		Reason:           reason,
		RequestedMinutes: minutes,
		Status:           StatusPending,
		CreatedAt:        now,
		PendingExpiresAt: now.Add(s.opts.PendingTimeout),
		ExpiresAt:        now.Add(duration),
	}
	if err := s.update(func(data *fileData) error {
		data.Grants = append(data.Grants, grant)
		return nil
	}); err != nil {
		return Grant{}, err
	}
	return grant, nil
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
		data.Grants[index] = grant
		return nil
	})
}

// MatchActive returns an active grant for client, operation, target, and ref.
func (s *Store) MatchActive(client, operation, target, ref string) (Grant, bool, error) {
	var out Grant
	found := false
	err := s.update(func(data *fileData) error {
		for _, grant := range data.Grants {
			if grant.Status == StatusActive && grant.Client == client && grant.Operation == operation && grant.Target == target && grant.Ref == ref {
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
		grant.UsedAt = s.opts.Now().UTC()
		data.Grants[index] = grant
		out = grant
		return nil
	})
	return out, err
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
	return data, nil
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
	now := s.opts.Now().UTC()
	changed := false
	for i := range data.Grants {
		grant := data.Grants[i]
		switch grant.Status {
		case StatusPending:
			if !now.Before(grant.PendingExpiresAt) {
				grant.Status = StatusExpired
				grant.DecidedAt = now
				changed = true
			}
		case StatusActive:
			if !now.Before(grant.ExpiresAt) {
				grant.Status = StatusExpired
				changed = true
			}
		}
		data.Grants[i] = grant
	}
	return changed
}

func (s *Store) findGrant(data *fileData, id string) (int, Grant, error) {
	for i, grant := range data.Grants {
		if grant.ID == id {
			return i, grant, nil
		}
	}
	return -1, Grant{}, ErrNotFound
}

func randomID(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate grant id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
