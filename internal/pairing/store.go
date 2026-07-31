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
	mu        sync.Mutex
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
		return pairingv1.Bundle{}, ErrGone
	}
	if store.now().After(record.InvitationExpires) {
		_ = store.expire(&record)
		return pairingv1.Bundle{}, ErrGone
	}
	if !matchesHash(record.InvitationTokenHash, token) {
		return pairingv1.Bundle{}, ErrForbidden
	}
	record.State, record.InvitationTokenHash, record.UpdatedAt = StateClaimed, "", store.now()
	if err := store.save(record); err != nil {
		return pairingv1.Bundle{}, err
	}
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
	return store.save(record)
}

func (store *Store) claimTransition(id, secret string, allowed []string, next string, erase bool) (Record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	record, err := store.loadCurrent(id)
	if err != nil {
		return Record{}, err
	}
	if !matchesHash(record.ClaimSecretHash, secret) {
		return Record{}, ErrForbidden
	}
	valid := false
	for _, state := range allowed {
		valid = valid || record.State == state
	}
	if !valid {
		return Record{}, ErrGone
	}
	record.State, record.UpdatedAt = next, store.now()
	if erase {
		record.Bundle, record.InvitationTokenHash, record.ClaimSecretHash = pairingv1.Bundle{}, "", ""
	}
	if err := store.save(record); err != nil {
		return Record{}, err
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
	return store.save(*record)
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
