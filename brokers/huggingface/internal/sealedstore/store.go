// Package sealedstore stores short-lived encrypted operation payloads outside
// the broker database. Plaintext is available only during exact execution.
package sealedstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/securefile"
)

const (
	keyBytes       = 32
	maxSecretBytes = 1 << 20
	formatVersion  = 2
	maxStoredFiles = 256
	maxStoredBytes = 64 << 20
	maxFileBytes   = 2 << 20
)

var referencePattern = regexp.MustCompile(`^sealed_[A-Za-z0-9_-]{24}$`)
var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9._@:-]{1,128}$`)
var purposePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+$`)

type Reference struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Purpose    string `json:"purpose"`
	RequestKey string `json:"request_key"`
	Digest     string `json:"digest"`
	Size       int    `json:"size"`
	ExpiresAt  int64  `json:"expires_at"`
}

type diskEnvelope struct {
	Version    int       `json:"version"`
	Reference  Reference `json:"reference"`
	Nonce      []byte    `json:"nonce"`
	Ciphertext []byte    `json:"ciphertext"`
}

type Store struct {
	dir  string
	aead cipher.AEAD
	mu   sync.Mutex
}

func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("sealed payload state directory is required")
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, errors.New("create sealed payload state directory")
	}
	key, err := loadOrCreateKey(filepath.Join(stateDir, "sealed-payload.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize sealed payload cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize sealed payload encryption")
	}
	dir := filepath.Join(stateDir, "sealed-payloads")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, errors.New("create sealed payload directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- directories require execute permission and remain owner-only.
		return nil, errors.New("secure sealed payload directory")
	}
	store := &Store{dir: dir, aead: aead}
	if _, err := store.SweepExpired(time.Now()); err != nil {
		return nil, err
	}
	return store, nil
}

//nolint:cyclop // Encryption and collision checks are explicit and tracked by the exact HF CRAP baseline.
func (s *Store) Put(owner, purpose string, plaintext []byte, expiresAt time.Time) (Reference, error) {
	requestKey, err := randomReference()
	if err != nil {
		return Reference{}, errors.New("generate sealed payload request key")
	}
	return s.PutForRequest(owner, purpose, requestKey, plaintext, expiresAt)
}

// PutForRequest creates or idempotently returns the encrypted payload for one
// operation submission key. Reusing the key with different plaintext fails.
func (s *Store) PutForRequest(owner, purpose, requestKey string, plaintext []byte, expiresAt time.Time) (Reference, error) {
	now := time.Now()
	if s == nil || s.aead == nil || len(plaintext) == 0 || len(plaintext) > maxSecretBytes || !ownerPattern.MatchString(owner) ||
		!purposePattern.MatchString(purpose) || !validRequestKey(requestKey) || expiresAt.Before(now) || expiresAt.After(now.Add(24*time.Hour)) {
		return Reference{}, errors.New("sealed payload is invalid")
	}
	digest := sha256.Sum256(plaintext)
	digestText := hex.EncodeToString(digest[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.sweepLocked(now); err != nil {
		return Reference{}, err
	}
	if existing, found, err := s.findRequestLocked(owner, purpose, requestKey, digestText, len(plaintext)); err != nil || found {
		return existing, err
	}
	for range 8 {
		reference, err := randomReference()
		if err != nil {
			return Reference{}, errors.New("generate sealed payload reference")
		}
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return Reference{}, errors.New("generate sealed payload nonce")
		}
		bound := Reference{ID: reference, Owner: owner, Purpose: purpose, RequestKey: requestKey,
			Digest: digestText, Size: len(plaintext), ExpiresAt: expiresAt.Unix()}
		ciphertext := s.aead.Seal(nil, nonce, plaintext, associatedData(bound))
		encoded, err := json.Marshal(diskEnvelope{Version: formatVersion, Reference: bound, Nonce: nonce, Ciphertext: ciphertext})
		if err != nil || len(encoded) > maxFileBytes {
			return Reference{}, errors.New("encode sealed payload")
		}
		if err := s.checkQuotaLocked(int64(len(encoded))); err != nil {
			return Reference{}, err
		}
		path := s.path(reference)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- random filename under the fixed store directory.
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return Reference{}, errors.New("create sealed payload")
		}
		writeErr := securefile.WriteAndSync(file, encoded, "sealed payload")
		if writeErr != nil {
			_ = os.Remove(path)
			return Reference{}, writeErr
		}
		return bound, nil
	}
	return Reference{}, errors.New("allocate sealed payload reference")
}

// SweepExpired removes expired payloads and incomplete consume claims.
func (s *Store) SweepExpired(now time.Time) (int, error) {
	if s == nil || s.aead == nil {
		return 0, errors.New("sealed payload store is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(now)
}

func (s *Store) Get(reference Reference) ([]byte, error) {
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(reference, s.path(reference.ID))
}

// Consume atomically claims, decrypts, and removes one payload. A second
// caller cannot observe the plaintext even when executions race.
func (s *Store) Consume(reference Reference) ([]byte, error) {
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	source := s.path(reference.ID)
	claimed := source + ".consuming"
	if err := os.Rename(source, claimed); err != nil {
		return nil, errors.New("sealed payload is unavailable")
	}
	defer func() { _ = os.Remove(claimed) }()
	return s.read(reference, claimed)
}

func (s *Store) Delete(reference Reference) error {
	if err := validateReference(reference); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(reference.ID))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("delete sealed payload")
	}
	return nil
}

func (s *Store) read(reference Reference, path string) ([]byte, error) {
	if time.Now().Unix() >= reference.ExpiresAt {
		return nil, errors.New("sealed payload is expired")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from a validated random reference.
	if err != nil || len(data) == 0 || len(data) > maxFileBytes {
		return nil, errors.New("sealed payload is unavailable")
	}
	var envelope diskEnvelope
	if json.Unmarshal(data, &envelope) != nil || envelope.Version != formatVersion || envelope.Reference != reference ||
		len(envelope.Nonce) != s.aead.NonceSize() || len(envelope.Ciphertext) < s.aead.Overhead() {
		return nil, errors.New("sealed payload format is unsupported")
	}
	plaintext, err := s.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData(reference))
	if err != nil {
		return nil, errors.New("sealed payload authentication failed")
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != reference.Digest || len(plaintext) != reference.Size {
		return nil, errors.New("sealed payload binding failed")
	}
	return plaintext, nil
}

func (s *Store) sweepLocked(now time.Time) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, errors.New("scan sealed payload directory")
	}
	removed := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".bin") && !strings.HasSuffix(name, ".bin.consuming") {
			continue
		}
		path := filepath.Join(s.dir, name)
		if strings.HasSuffix(name, ".consuming") {
			if os.Remove(path) == nil {
				removed++
			}
			continue
		}
		envelope, readErr := readDiskEnvelope(path)
		invalid := readErr != nil || envelope.Version != formatVersion || validateReference(envelope.Reference) != nil ||
			name != envelope.Reference.ID+".bin"
		if invalid || now.Unix() >= envelope.Reference.ExpiresAt {
			if os.Remove(path) == nil {
				removed++
			}
		}
	}
	return removed, nil
}

func (s *Store) findRequestLocked(owner, purpose, requestKey, digest string, size int) (Reference, bool, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return Reference{}, false, errors.New("scan sealed payload directory")
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bin") {
			continue
		}
		envelope, readErr := readDiskEnvelope(filepath.Join(s.dir, entry.Name()))
		if readErr != nil {
			continue
		}
		reference := envelope.Reference
		if reference.Owner != owner || reference.Purpose != purpose || reference.RequestKey != requestKey {
			continue
		}
		if reference.Digest != digest || reference.Size != size {
			return Reference{}, false, errors.New("sealed payload idempotency conflict")
		}
		return reference, true, nil
	}
	return Reference{}, false, nil
}

func (s *Store) checkQuotaLocked(additionalBytes int64) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return errors.New("scan sealed payload directory")
	}
	count := 0
	var total int64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".bin") {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return errors.New("inspect sealed payload quota")
		}
		count++
		total += info.Size()
	}
	if count >= maxStoredFiles || additionalBytes <= 0 || total+additionalBytes > maxStoredBytes {
		return errors.New("sealed payload quota exceeded")
	}
	return nil
}

func readDiskEnvelope(path string) (diskEnvelope, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller supplies a path discovered under the fixed store directory.
	if err != nil || len(data) == 0 || len(data) > maxFileBytes {
		return diskEnvelope{}, errors.New("sealed payload envelope is unavailable")
	}
	var envelope diskEnvelope
	if json.Unmarshal(data, &envelope) != nil {
		return diskEnvelope{}, errors.New("sealed payload envelope is invalid")
	}
	return envelope, nil
}

func (s *Store) path(reference string) string { return filepath.Join(s.dir, reference+".bin") }

//nolint:cyclop // Key integrity checks are explicit and tracked by the exact HF CRAP baseline.
func loadOrCreateKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- installation-owned fixed path.
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("sealed payload key permissions are unsafe")
		}
		decoded, decodeErr := base64.RawStdEncoding.DecodeString(string(data))
		if decodeErr != nil || len(decoded) != keyBytes {
			return nil, errors.New("sealed payload key is invalid")
		}
		return decoded, nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read sealed payload key")
	}
	key := make([]byte, keyBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("generate sealed payload key")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed installation-owned key path.
	if err != nil {
		return nil, errors.New("create sealed payload key")
	}
	if err := securefile.WriteAndSync(file, []byte(base64.RawStdEncoding.EncodeToString(key)), "sealed payload"); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

func randomReference() (string, error) {
	data := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return "sealed_" + base64.RawURLEncoding.EncodeToString(data), nil
}

func validateReference(reference Reference) error {
	if !referencePattern.MatchString(reference.ID) || !ownerPattern.MatchString(reference.Owner) || !purposePattern.MatchString(reference.Purpose) ||
		!validRequestKey(reference.RequestKey) || len(reference.Digest) != sha256.Size*2 || reference.Size <= 0 || reference.Size > maxSecretBytes || reference.ExpiresAt <= 0 {
		return errors.New("sealed payload reference is invalid")
	}
	if _, err := hex.DecodeString(reference.Digest); err != nil {
		return fmt.Errorf("sealed payload reference is invalid")
	}
	return nil
}

func validRequestKey(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\t\r\n")
}

func associatedData(reference Reference) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d", reference.ID, reference.Owner, reference.Purpose,
		reference.RequestKey, reference.Size, reference.ExpiresAt))
}
