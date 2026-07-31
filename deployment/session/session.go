// Package session stores resumable nonsecret guided setup progress.
package session

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/osolmaz/unyolo/internal/securefile"
	"github.com/osolmaz/unyolo/internal/strictjson"
	setupintent "github.com/osolmaz/unyolo/setup/intent"
)

const (
	APIVersion      = "unyolo.io/setup-session/v1"
	MaxSessionBytes = 1024 * 1024
)

var (
	fieldIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Phase identifies the last committed nonsecret setup boundary.
type Phase string

const (
	PhaseStarted   Phase = "started"
	PhaseEnrolling Phase = "enrolling"
	PhaseProfile   Phase = "profile_ready"
	PhasePlanned   Phase = "planned"
	PhaseApplying  Phase = "applying"
	PhaseComplete  Phase = "complete"
	PhaseCancelled Phase = "cancelled"
)

// SecretSlot records only whether a secret must be supplied again.
type SecretSlot struct {
	ID       string `json:"id"`
	Supplied bool   `json:"supplied"`
}

// Session is one resumable nonsecret setup session.
type Session struct {
	APIVersion       string             `json:"api_version"`
	ID               string             `json:"id"`
	BuildID          string             `json:"build_id"`
	InstallationName string             `json:"installation_name"`
	Intent           setupintent.Intent `json:"setup_intent"`
	CurrentStep      string             `json:"current_step_id,omitempty"`
	CompletedStep    []string           `json:"completed_step_ids"`
	CapabilityDigest string             `json:"capability_snapshot_digest,omitempty"`
	SecretSlots      []SecretSlot       `json:"secret_slots"`
	Generated        map[string]string  `json:"generated_file_digests"`
	Phase            Phase              `json:"phase"`
	LastSafeError    string             `json:"last_safe_error,omitempty"`
	CreatedAt        time.Time          `json:"created_at"`
	UpdatedAt        time.Time          `json:"updated_at"`
}

// Store owns setup sessions below one operator state directory.
type Store struct {
	Directory string
	Now       func() time.Time
}

// UnreadableSessionsError identifies saved setup progress that cannot be used
// by the current release. The files remain untouched until the user explicitly
// chooses to discard them.
type UnreadableSessionsError struct {
	ids []string
}

func (err *UnreadableSessionsError) Error() string {
	return "saved setup progress cannot be opened"
}

// SessionIDs returns the exact saved-progress files that could not be decoded
// or validated.
func (err *UnreadableSessionsError) SessionIDs() []string {
	return append([]string(nil), err.ids...)
}

type unreadableSessionError struct {
	id  string
	err error
}

func (err *unreadableSessionError) Error() string {
	return fmt.Sprintf("read setup session %s: %v", err.id, err.err)
}

func (err *unreadableSessionError) Unwrap() error {
	return err.err
}

// DefaultDirectory returns the current user's setup state directory.
func DefaultDirectory() (string, error) {
	var state string
	if value := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); value != "" {
		if !filepath.IsAbs(value) {
			return "", errors.New("XDG_STATE_HOME must be absolute")
		}
		state = value
	} else {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return "", homeErr
		}
		state = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(state, "unyolo", "setup"), nil
}

// New creates an in-memory session with a random identity.
func New(buildID string, now time.Time) (Session, error) {
	if strings.TrimSpace(buildID) == "" {
		return Session{}, errors.New("setup build identity is required")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Session{}, fmt.Errorf("create setup session ID: %w", err)
	}
	return Session{
		APIVersion: APIVersion, ID: hex.EncodeToString(random[:]), BuildID: buildID, InstallationName: "default",
		Intent: setupintent.Intent{APIVersion: setupintent.APIVersion}, Generated: map[string]string{},
		Phase: PhaseStarted, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

// Save writes a session atomically with owner-only permissions.
func (store Store) Save(value Session) error {
	for index := range value.SecretSlots {
		value.SecretSlots[index].Supplied = false
	}
	if err := value.Validate(); err != nil {
		return err
	}
	if err := ensureDirectory(store.Directory); err != nil {
		return err
	}
	value.UpdatedAt = store.now().UTC()
	data, err := marshal(value)
	if err != nil {
		return err
	}
	return writeAtomic(store.Directory, value.ID+".json", data)
}

// Load reads one exact session.
func (store Store) Load(id string) (Session, error) {
	if !validID(id) {
		return Session{}, errors.New("setup session ID is invalid")
	}
	path := filepath.Join(store.Directory, id+".json")
	info, err := os.Lstat(path)
	if err != nil {
		return Session{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return Session{}, errors.New("setup session must be a regular owner-only file")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- ID and directory are validated.
	if err != nil {
		return Session{}, err
	}
	if len(data) > MaxSessionBytes {
		return Session{}, &unreadableSessionError{id: id, err: errors.New("setup session exceeds size limit")}
	}
	var value Session
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Session{}, &unreadableSessionError{id: id, err: fmt.Errorf("decode setup session: %w", err)}
	}
	if err := value.Validate(); err != nil {
		return Session{}, &unreadableSessionError{id: id, err: err}
	}
	return value, nil
}

// List returns all valid sessions, newest first.
func (store Store) List() ([]Session, error) {
	entries, err := os.ReadDir(store.Directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	values := make([]Session, 0, len(entries))
	var unreadableIDs []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		value, loadErr := store.Load(strings.TrimSuffix(entry.Name(), ".json"))
		if loadErr != nil {
			var unreadable *unreadableSessionError
			if errors.As(loadErr, &unreadable) {
				unreadableIDs = append(unreadableIDs, unreadable.id)
				continue
			}
			return nil, loadErr
		}
		values = append(values, value)
	}
	if len(unreadableIDs) != 0 {
		slices.Sort(unreadableIDs)
		return nil, &UnreadableSessionsError{ids: unreadableIDs}
	}
	slices.SortFunc(values, func(a, b Session) int { return b.UpdatedAt.Compare(a.UpdatedAt) })
	return values, nil
}

// DiscardUnreadable removes only exact owner-only session files that still
// fail the current strict decoder. It never interprets or converts old state.
func (store Store) DiscardUnreadable(ids []string) error {
	unique := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !validID(id) {
			return errors.New("setup session ID is invalid")
		}
		if _, found := unique[id]; found {
			return errors.New("setup session ID is duplicated")
		}
		unique[id] = struct{}{}
	}
	ordered := make([]string, 0, len(unique))
	for id := range unique {
		ordered = append(ordered, id)
	}
	slices.Sort(ordered)
	for _, id := range ordered {
		if _, err := store.Load(id); err == nil {
			return errors.New("setup session became readable; refusing to discard it")
		} else {
			var unreadable *unreadableSessionError
			if !errors.As(err, &unreadable) {
				return err
			}
		}
	}
	for _, id := range ordered {
		if err := os.Remove(filepath.Join(store.Directory, id+".json")); err != nil {
			return err
		}
	}
	return nil
}

// NewestIncomplete returns the newest compatible resumable session.
func (store Store) NewestIncomplete(buildID string) (Session, bool, error) {
	entries, err := store.List()
	if err != nil {
		return Session{}, false, err
	}
	var candidates []Session
	for _, value := range entries {
		if value.BuildID == buildID && value.Phase != PhaseComplete && value.Phase != PhaseCancelled {
			candidates = append(candidates, value)
		}
	}
	if len(candidates) == 0 {
		return Session{}, false, nil
	}
	slices.SortFunc(candidates, func(a, b Session) int { return b.UpdatedAt.Compare(a.UpdatedAt) })
	return candidates[0], true, nil
}

// Cancel removes one uncommitted local session.
func (store Store) Cancel(id string) error {
	value, err := store.Load(id)
	if err != nil {
		return err
	}
	if value.Phase == PhaseApplying || value.Phase == PhaseComplete {
		return errors.New("committed or active host setup cannot be cancelled locally")
	}
	return os.Remove(filepath.Join(store.Directory, id+".json"))
}

// Validate rejects malformed or secret-like setup state structure.
//
//nolint:cyclop // Resumable state is checked exhaustively to keep secret-bearing fields out of persistence.
func (value Session) Validate() error {
	if value.APIVersion != APIVersion || !validID(value.ID) || strings.TrimSpace(value.BuildID) == "" || value.InstallationName != "default" {
		return errors.New("setup session identity is invalid")
	}
	if err := value.Intent.ValidatePartial(); err != nil {
		return fmt.Errorf("setup session intent: %w", err)
	}
	if value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return errors.New("setup session timestamps are invalid")
	}
	if !slices.Contains([]Phase{PhaseStarted, PhaseEnrolling, PhaseProfile, PhasePlanned, PhaseApplying, PhaseComplete, PhaseCancelled}, value.Phase) {
		return errors.New("setup session phase is invalid")
	}
	if len(value.CompletedStep) > 256 || len(value.SecretSlots) > 64 || len(value.Generated) > 256 || len(value.LastSafeError) > 4096 {
		return errors.New("setup session exceeds collection limits")
	}
	if value.CurrentStep != "" && !fieldIDPattern.MatchString(value.CurrentStep) || value.CapabilityDigest != "" && !digestPattern.MatchString(value.CapabilityDigest) {
		return errors.New("setup session step or capability digest is invalid")
	}
	seenSteps := map[string]bool{}
	for _, step := range value.CompletedStep {
		if !fieldIDPattern.MatchString(step) || seenSteps[step] {
			return errors.New("setup completed step is invalid or duplicated")
		}
		seenSteps[step] = true
	}
	seenSlots := map[string]bool{}
	for _, slot := range value.SecretSlots {
		if !fieldIDPattern.MatchString(slot.ID) || seenSlots[slot.ID] || slot.Supplied {
			return errors.New("setup secret slot ID is invalid or duplicated")
		}
		seenSlots[slot.ID] = true
	}
	for path, digest := range value.Generated {
		if strings.TrimSpace(path) == "" || !digestPattern.MatchString(digest) {
			return errors.New("setup generated file digest is invalid")
		}
	}
	return nil
}

func (store Store) now() time.Time {
	if store.Now != nil {
		return store.Now()
	}
	return time.Now()
}

func ensureDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("setup session directory must be absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return errors.New("setup session directory must be a real owner-only directory")
	}
	return nil
}

func marshal(value Session) ([]byte, error) {
	data, err := jsonMarshalIndent(value)
	if len(data) > MaxSessionBytes {
		return nil, errors.New("setup session exceeds size limit")
	}
	return data, err
}

var jsonMarshalIndent = func(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	return append(data, '\n'), err
}

func writeAtomic(directory, name string, data []byte) error {
	return securefile.AtomicWrite(filepath.Join(directory, name), data, 0o600, "setup session")
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
