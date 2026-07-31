// Package pairing implements durable one-use remote client enrollment.
package pairing

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/unyolo/internal/securefile"
	"github.com/osolmaz/unyolo/internal/strictjson"
	pairingv1 "github.com/osolmaz/unyolo/protocol/pairing"
)

const (
	StateOffered  = "offered"
	StateClaimed  = "claimed"
	StateReady    = "ready"
	StateActive   = "active"
	StateVerified = "verified"
	StateExpired  = "expired"
	StateRevoked  = "revoked"
)

// Event names emitted through the pairing audit stream. These are safe to log
// and never carry secret material.
const (
	EventOffered  = "invitation.offered"
	EventClaimed  = "invitation.claimed"
	EventReady    = "connection.ready"
	EventActive   = "connection.active"
	EventVerified = "connection.verified"
	EventExpired  = "invitation.expired"
	EventRevoked  = "invitation.revoked"
	EventPurged   = "invitation.purged"
	EventDenied   = "invitation.denied"
)

// Event is a safe, secret-free record of one pairing lifecycle transition.
type Event struct {
	Name      string    `json:"name"`
	PairingID string    `json:"pairing_id"`
	State     string    `json:"state"`
	At        time.Time `json:"at"`
	Reason    string    `json:"reason,omitempty"`
}

// AuditSink receives Events for every lifecycle transition. It must not
// receive secrets; the store guarantees Event contains only nonsecret fields.
type AuditSink interface {
	Emit(Event)
}

// AuditFunc adapts a function to AuditSink.
type AuditFunc func(Event)

// Emit forwards the event to the underlying function.
func (f AuditFunc) Emit(event Event) {
	if f != nil {
		f(event)
	}
}

var (
	ErrGone      = errors.New("pairing invitation is no longer available")
	ErrForbidden = errors.New("pairing credential is invalid")
	idPattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
)

type Record struct {
	APIVersion          string           `json:"api_version"`
	ID                  string           `json:"id"`
	State               string           `json:"state"`
	InvitationTokenHash string           `json:"invitation_token_hash"`
	ClaimSecretHash     string           `json:"claim_secret_hash"`
	Bundle              pairingv1.Bundle `json:"bundle,omitempty"`
	InvitationExpires   time.Time        `json:"invitation_expires_at"`
	CompletionExpires   time.Time        `json:"completion_expires_at"`
	UpdatedAt           time.Time        `json:"updated_at"`
}

type InvitationOptions struct {
	ID            string
	Endpoint      string
	CACertificate []byte
	ServerName    string
	ExpiresAt     time.Time
	Bundle        pairingv1.Bundle
}

type Store struct {
	Directory string
	Now       func() time.Time
	Audit     AuditSink
	mu        sync.Mutex
}

func (store *Store) emit(name string, record Record, reason string) {
	if store.Audit == nil {
		return
	}
	store.Audit.Emit(Event{Name: name, PairingID: record.ID, State: record.State, At: store.now(), Reason: reason})
}

func (store *Store) Create(options InvitationOptions) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !validID(options.ID) || options.ExpiresAt.IsZero() || !options.ExpiresAt.After(store.now()) {
		return "", errors.New("pairing invitation options are invalid")
	}
	if err := ensureDirectory(store.Directory); err != nil {
		return "", err
	}
	if _, err := os.Lstat(store.path(options.ID)); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", errors.New("pairing invitation already exists")
	}
	invitationToken, err := randomSecret()
	if err != nil {
		return "", err
	}
	claimSecret, err := randomSecret()
	if err != nil {
		return "", err
	}
	options.Bundle.APIVersion = pairingv1.APIVersion
	options.Bundle.PairingID = options.ID
	options.Bundle.ClaimSecret = claimSecret
	options.Bundle.CACertificate = base64.RawStdEncoding.EncodeToString(options.CACertificate)
	if err := options.Bundle.Validate(); err != nil {
		return "", err
	}
	now := store.now()
	record := Record{
		APIVersion: pairingv1.APIVersion, ID: options.ID, State: StateOffered,
		InvitationTokenHash: tokenHash(invitationToken), ClaimSecretHash: tokenHash(claimSecret), Bundle: options.Bundle,
		InvitationExpires: options.ExpiresAt.UTC(), CompletionExpires: options.ExpiresAt.UTC().Add(time.Hour), UpdatedAt: now,
	}
	if err := store.save(record); err != nil {
		return "", err
	}
	store.emit(EventOffered, record, "")
	certificate := base64.RawStdEncoding.EncodeToString(options.CACertificate)
	invitation := pairingv1.Invitation{
		APIVersion: pairingv1.APIVersion, Endpoint: options.Endpoint, PairingID: options.ID, Token: invitationToken,
		CACertificate: certificate, CAFingerprint: fmt.Sprintf("sha256:%x", sha256.Sum256(options.CACertificate)),
		ServerName: options.ServerName, ExpiresAt: options.ExpiresAt.UTC(),
	}
	return pairingv1.EncodeInvitation(invitation)
}

func (store *Store) Claim(id, token string) (pairingv1.Bundle, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadCurrent(id)
	if err != nil {
		return pairingv1.Bundle{}, err
	}
	if record.State != StateOffered {
		store.emit(EventDenied, record, "not-offered")
		return pairingv1.Bundle{}, ErrGone
	}
	if store.now().After(record.InvitationExpires) {
		_ = store.expire(&record)
		return pairingv1.Bundle{}, ErrGone
	}
	if !matchesHash(record.InvitationTokenHash, token) {
		store.emit(EventDenied, record, "wrong-token")
		return pairingv1.Bundle{}, ErrForbidden
	}
	record.State, record.InvitationTokenHash, record.UpdatedAt = StateClaimed, "", store.now()
	if err := store.save(record); err != nil {
		return pairingv1.Bundle{}, err
	}
	store.emit(EventClaimed, record, "")
	return record.Bundle, nil
}

func (store *Store) Ready(id, claimSecret string) (Record, error) {
	return store.claimTransition(id, claimSecret, []string{StateClaimed, StateReady}, StateReady, false)
}

func (store *Store) Verified(id, claimSecret string) (Record, error) {
	return store.claimTransition(id, claimSecret, []string{StateActive, StateVerified}, StateVerified, true)
}

func (store *Store) Activate(id string) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadCurrent(id)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateReady {
		return Record{}, errors.New("pairing is not ready for activation")
	}
	record.State, record.UpdatedAt = StateActive, store.now()
	if err := store.save(record); err != nil {
		return Record{}, err
	}
	store.emit(EventActive, record, "")
	return redacted(record), nil
}

func (store *Store) Status(id, claimSecret string) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadCurrent(id)
	if err != nil {
		return Record{}, err
	}
	if !matchesHash(record.ClaimSecretHash, claimSecret) {
		return Record{}, ErrForbidden
	}
	return redacted(record), nil
}

func (store *Store) LocalStatus(id string) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadCurrent(id)
	return redacted(record), err
}

func (store *Store) Revoke(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.load(id)
	if err != nil {
		return err
	}
	if record.State == StateActive || record.State == StateVerified {
		return errors.New("active pairing requires a connection-removal plan")
	}
	record.State, record.Bundle, record.InvitationTokenHash, record.ClaimSecretHash = StateRevoked, pairingv1.Bundle{}, "", ""
	record.UpdatedAt = store.now()
	if err := store.save(record); err != nil {
		return err
	}
	store.emit(EventRevoked, record, "")
	return nil
}

// PurgeExpired walks the store and expires every offered/claimed/ready record
// whose completion window has passed, erasing every remaining bundle from
// disk. Records already terminal (verified, expired, revoked) whose retention
// window has passed are removed entirely so no orphan bundles remain.
func (store *Store) PurgeExpired(retention time.Duration) (int, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, err := os.Lstat(store.Directory); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	entries, err := os.ReadDir(store.Directory)
	if err != nil {
		return 0, err
	}
	if retention < 0 {
		retention = 0
	}
	now := store.now()
	changed := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			continue
		}
		id := strings.TrimSuffix(name, ".json")
		if !validID(id) {
			continue
		}
		record, err := store.load(id)
		if err != nil {
			continue
		}
		switch record.State {
		case StateOffered, StateClaimed, StateReady:
			if !now.After(record.CompletionExpires) {
				continue
			}
			if err := store.expire(&record); err != nil {
				return changed, err
			}
			changed++
		case StateActive:
			continue
		case StateVerified, StateExpired, StateRevoked:
			if !now.After(record.UpdatedAt.Add(retention)) {
				continue
			}
			if err := os.Remove(store.path(id)); err != nil {
				return changed, err
			}
			store.emit(EventPurged, record, "")
			changed++
		}
	}
	return changed, nil
}

func (store *Store) claimTransition(id, secret string, allowed []string, next string, erase bool) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadCurrent(id)
	if err != nil {
		return Record{}, err
	}
	if !matchesHash(record.ClaimSecretHash, secret) {
		store.emit(EventDenied, record, "wrong-claim-secret")
		return Record{}, ErrForbidden
	}
	valid := false
	for _, state := range allowed {
		valid = valid || record.State == state
	}
	if !valid {
		store.emit(EventDenied, record, "invalid-transition")
		return Record{}, ErrGone
	}
	record.State, record.UpdatedAt = next, store.now()
	if erase {
		record.Bundle, record.InvitationTokenHash, record.ClaimSecretHash = pairingv1.Bundle{}, "", ""
	}
	if err := store.save(record); err != nil {
		return Record{}, err
	}
	switch next {
	case StateReady:
		store.emit(EventReady, record, "")
	case StateVerified:
		store.emit(EventVerified, record, "")
	}
	return redacted(record), nil
}

func (store *Store) loadCurrent(id string) (Record, error) {
	record, err := store.load(id)
	if err != nil {
		return Record{}, err
	}
	if store.now().After(record.CompletionExpires) && record.State != StateActive && record.State != StateVerified {
		if err := store.expire(&record); err != nil {
			return Record{}, err
		}
		return Record{}, ErrGone
	}
	return record, nil
}

func (store *Store) expire(record *Record) error {
	record.State, record.Bundle, record.InvitationTokenHash, record.ClaimSecretHash = StateExpired, pairingv1.Bundle{}, "", ""
	record.UpdatedAt = store.now()
	if err := store.save(*record); err != nil {
		return err
	}
	store.emit(EventExpired, *record, "")
	return nil
}

func (store *Store) load(id string) (Record, error) {
	if !validID(id) {
		return Record{}, errors.New("pairing ID is invalid")
	}
	info, err := os.Lstat(store.path(id))
	if err != nil {
		return Record{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 || info.Size() > pairingv1.MaxMessageBytes {
		return Record{}, errors.New("pairing record is unsafe")
	}
	data, err := os.ReadFile(store.path(id)) // #nosec G304 -- ID is validated and directory is fixed.
	if err != nil {
		return Record{}, err
	}
	var record Record
	if err := strictjson.Decode(data, &record, true); err != nil || record.APIVersion != pairingv1.APIVersion || record.ID != id {
		return Record{}, errors.New("pairing record is invalid")
	}
	return record, nil
}

func (store *Store) save(record Record) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil || len(data) > pairingv1.MaxMessageBytes {
		return errors.New("pairing record exceeds size limit")
	}
	data = append(data, '\n')
	return securefile.AtomicWrite(store.path(record.ID), data, 0o600, "pairing record")
}

func (store *Store) path(id string) string { return filepath.Join(store.Directory, id+".json") }
func (store *Store) now() time.Time {
	if store.Now != nil {
		return store.Now().UTC()
	}
	return time.Now().UTC()
}

func ensureDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("pairing state directory must be absolute and clean")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("pairing state directory is unsafe")
	}
	return nil
}

func randomSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func tokenHash(value string) string { return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value))) }
func matchesHash(expected, token string) bool {
	if !strings.HasPrefix(expected, "sha256:") || len(expected) != 71 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(expected, "sha256:"))
	actual := sha256.Sum256([]byte(token))
	return err == nil && subtle.ConstantTimeCompare(decoded, actual[:]) == 1
}
func validID(value string) bool { return len(value) <= 64 && idPattern.MatchString(value) }
func redacted(record Record) Record {
	record.Bundle, record.InvitationTokenHash, record.ClaimSecretHash = pairingv1.Bundle{}, "", ""
	return record
}
