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

	"github.com/osolmaz/brokerkit/internal/strictjson"
)

const (
	APIVersion      = "brokerkit.io/setup-session/v1"
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
	APIVersion    string              `json:"api_version"`
	ID            string              `json:"id"`
	BuildID       string              `json:"build_id"`
	Deployment    string              `json:"deployment"`
	CompletedStep []string            `json:"completed_step_ids"`
	Answers       map[string][]string `json:"answers"`
	SecretSlots   []SecretSlot        `json:"secret_slots"`
	Generated     map[string]string   `json:"generated_file_digests"`
	Phase         Phase               `json:"phase"`
	LastSafeError string              `json:"last_safe_error,omitempty"`
	CreatedAt     time.Time           `json:"created_at"`
	UpdatedAt     time.Time           `json:"updated_at"`
}

// Store owns setup sessions below one operator state directory.
type Store struct {
	Directory string
	Now       func() time.Time
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
	return filepath.Join(state, "brokerkit", "setup"), nil
}

// New creates an in-memory session with a random identity.
func New(buildID, deployment string, now time.Time) (Session, error) {
	if strings.TrimSpace(buildID) == "" || strings.TrimSpace(deployment) == "" {
		return Session{}, errors.New("setup build and deployment names are required")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return Session{}, fmt.Errorf("create setup session ID: %w", err)
	}
	return Session{
		APIVersion: APIVersion, ID: hex.EncodeToString(random[:]), BuildID: buildID,
		Deployment: deployment, Answers: map[string][]string{}, Generated: map[string]string{},
		Phase: PhaseStarted, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

// Save writes a session atomically with owner-only permissions.
func (store Store) Save(value Session) error {
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
		return Session{}, errors.New("setup session exceeds size limit")
	}
	var value Session
	if err := strictjson.Decode(data, &value, true); err != nil {
		return Session{}, fmt.Errorf("decode setup session: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Session{}, err
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
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		value, loadErr := store.Load(strings.TrimSuffix(entry.Name(), ".json"))
		if loadErr != nil {
			return nil, loadErr
		}
		values = append(values, value)
	}
	slices.SortFunc(values, func(a, b Session) int { return b.UpdatedAt.Compare(a.UpdatedAt) })
	return values, nil
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
	if value.APIVersion != APIVersion || !validID(value.ID) || strings.TrimSpace(value.BuildID) == "" || strings.TrimSpace(value.Deployment) == "" {
		return errors.New("setup session identity is invalid")
	}
	if value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return errors.New("setup session timestamps are invalid")
	}
	if !slices.Contains([]Phase{PhaseStarted, PhaseEnrolling, PhaseProfile, PhasePlanned, PhaseApplying, PhaseComplete, PhaseCancelled}, value.Phase) {
		return errors.New("setup session phase is invalid")
	}
	if len(value.CompletedStep) > 256 || len(value.Answers) > 256 || len(value.SecretSlots) > 64 || len(value.Generated) > 256 || len(value.LastSafeError) > 4096 {
		return errors.New("setup session exceeds collection limits")
	}
	seenSteps := map[string]bool{}
	for _, step := range value.CompletedStep {
		if !fieldIDPattern.MatchString(step) || seenSteps[step] {
			return errors.New("setup completed step is invalid or duplicated")
		}
		seenSteps[step] = true
	}
	for key, answers := range value.Answers {
		lower := strings.ToLower(key)
		if !fieldIDPattern.MatchString(key) || strings.Contains(lower, "secret") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "password") || strings.Contains(lower, "credential") || len(answers) > 64 {
			return errors.New("setup answer key is invalid or secret-like")
		}
		for _, answer := range answers {
			if len(answer) > 4096 || strings.ContainsAny(answer, "\x00\r\n") {
				return errors.New("setup answer is invalid")
			}
		}
	}
	seenSlots := map[string]bool{}
	for _, slot := range value.SecretSlots {
		if !fieldIDPattern.MatchString(slot.ID) || seenSlots[slot.ID] {
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
	file, err := os.CreateTemp(directory, ".session-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, filepath.Join(directory, name))
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
