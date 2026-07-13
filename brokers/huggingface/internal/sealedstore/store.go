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
	Consumed   bool      `json:"consumed,omitempty"`
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
	return openStore(dir, aead)
}

func openStore(dir string, aead cipher.AEAD) (*Store, error) {
	store := &Store{dir: dir, aead: aead}
	if _, err := store.SweepExpired(time.Now()); err != nil {
		return nil, err
	}
	return store, nil
}

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
	if !validStore(s) || !validPutIdentity(owner, purpose, requestKey) || !validPutPayload(plaintext, expiresAt, now) {
		return Reference{}, errors.New("sealed payload is invalid")
	}
	digest := sha256.Sum256(plaintext)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(owner, purpose, requestKey, plaintext, hex.EncodeToString(digest[:]), expiresAt, now)
}

func validStore(store *Store) bool { return store != nil && store.aead != nil }

func validPutIdentity(owner, purpose, requestKey string) bool {
	return ownerPattern.MatchString(owner) && purposePattern.MatchString(purpose) && validRequestKey(requestKey)
}

func validPutPayload(plaintext []byte, expiresAt, now time.Time) bool {
	return len(plaintext) > 0 && len(plaintext) <= maxSecretBytes && !expiresAt.Before(now) && !expiresAt.After(now.Add(24*time.Hour))
}

func (s *Store) putLocked(owner, purpose, requestKey string, plaintext []byte, digest string, expiresAt, now time.Time) (Reference, error) {
	if _, err := s.sweepLocked(now); err != nil {
		return Reference{}, err
	}
	if existing, found, err := s.findRequestLocked(owner, purpose, requestKey, digest, len(plaintext)); err != nil || found {
		return existing, err
	}
	return s.createLocked(owner, purpose, requestKey, plaintext, digest, expiresAt)
}

func (s *Store) createLocked(owner, purpose, requestKey string, plaintext []byte, digest string, expiresAt time.Time) (Reference, error) {
	for range 8 {
		reference, encoded, err := s.encodePayload(owner, purpose, requestKey, plaintext, digest, expiresAt)
		if err != nil {
			return Reference{}, err
		}
		stored, err := s.persistEncodedLocked(reference.ID, encoded)
		if err != nil {
			return Reference{}, err
		}
		if stored {
			return reference, nil
		}
	}
	return Reference{}, errors.New("allocate sealed payload reference")
}

func (s *Store) persistEncodedLocked(id string, encoded []byte) (bool, error) {
	if err := s.checkQuotaLocked(int64(len(encoded))); err != nil {
		return false, err
	}
	path := s.path(id)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- random filename under the fixed store directory.
	if os.IsExist(err) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("create sealed payload")
	}
	if err := securefile.WriteAndSync(file, encoded, "sealed payload"); err != nil {
		_ = os.Remove(path)
		return false, err
	}
	return true, nil
}

func (s *Store) encodePayload(owner, purpose, requestKey string, plaintext []byte, digest string, expiresAt time.Time) (Reference, []byte, error) {
	id, err := randomReference()
	if err != nil {
		return Reference{}, nil, errors.New("generate sealed payload reference")
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Reference{}, nil, errors.New("generate sealed payload nonce")
	}
	reference := Reference{ID: id, Owner: owner, Purpose: purpose, RequestKey: requestKey,
		Digest: digest, Size: len(plaintext), ExpiresAt: expiresAt.Unix()}
	ciphertext := s.aead.Seal(nil, nonce, plaintext, associatedData(reference))
	encoded, err := json.Marshal(diskEnvelope{Version: formatVersion, Reference: reference, Nonce: nonce, Ciphertext: ciphertext})
	if err != nil || len(encoded) > maxFileBytes {
		return Reference{}, nil, errors.New("encode sealed payload")
	}
	return reference, encoded, nil
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

// Consume atomically decrypts one payload and replaces it with an authenticated
// consumed marker. The marker preserves submission idempotency without
// retaining plaintext, and a second caller cannot observe the secret.
func (s *Store) Consume(reference Reference) ([]byte, error) {
	if err := validateReference(reference); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := s.path(reference.ID)
	plaintext, err := s.read(reference, path)
	if err != nil {
		return nil, err
	}
	encoded, err := s.encodeConsumed(reference)
	if err != nil || s.replaceLocked(path, encoded) != nil {
		zero(plaintext)
		return nil, errors.New("consume sealed payload")
	}
	return plaintext, nil
}

func (s *Store) Delete(reference Reference) error {
	if err := validateReference(reference); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(reference, s.path(reference.ID))
}

func (s *Store) deleteLocked(reference Reference, path string) error {
	envelope, err := readDiskEnvelope(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("delete sealed payload")
	}
	if envelope.Consumed && s.validStoredEnvelope(envelope, filepath.Base(path)) {
		return nil
	}
	plaintext, err := s.read(reference, path)
	if err != nil {
		return err
	}
	zero(plaintext)
	encoded, err := s.encodeConsumed(reference)
	if err != nil {
		return err
	}
	return s.replaceLocked(path, encoded)
}

func (s *Store) encodeConsumed(reference Reference) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, errors.New("generate consumed payload nonce")
	}
	ciphertext := s.aead.Seal(nil, nonce, nil, consumedAssociatedData(reference))
	encoded, err := json.Marshal(diskEnvelope{Version: formatVersion, Reference: reference, Consumed: true, Nonce: nonce, Ciphertext: ciphertext})
	if err != nil || len(encoded) > maxFileBytes {
		return nil, errors.New("encode consumed payload marker")
	}
	return encoded, nil
}

func (s *Store) replaceLocked(path string, encoded []byte) error {
	file, temporary, err := s.replacementFile()
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary) }()
	if err := securefile.WriteAndSync(file, encoded, "sealed payload replacement"); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("replace sealed payload")
	}
	return nil
}

func (s *Store) replacementFile() (*os.File, string, error) {
	file, err := os.CreateTemp(s.dir, ".sealed-payload-*")
	if err != nil {
		return nil, "", errors.New("create sealed payload replacement")
	}
	temporary := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return nil, "", errors.New("secure sealed payload replacement")
	}
	return file, temporary, nil
}

func (s *Store) read(reference Reference, path string) ([]byte, error) {
	if time.Now().Unix() >= reference.ExpiresAt {
		return nil, errors.New("sealed payload is expired")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from a validated random reference.
	if err != nil || len(data) == 0 || len(data) > maxFileBytes {
		return nil, errors.New("sealed payload is unavailable")
	}
	envelope, err := decodeBoundEnvelope(data, reference, s.aead)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, associatedData(reference))
	if err != nil {
		return nil, errors.New("sealed payload authentication failed")
	}
	if !plaintextMatches(plaintext, reference) {
		return nil, errors.New("sealed payload binding failed")
	}
	return plaintext, nil
}

func decodeBoundEnvelope(data []byte, reference Reference, aead cipher.AEAD) (diskEnvelope, error) {
	var envelope diskEnvelope
	if json.Unmarshal(data, &envelope) != nil || !validBoundEnvelope(envelope, reference, aead) {
		return diskEnvelope{}, errors.New("sealed payload format is unsupported")
	}
	return envelope, nil
}

func validBoundEnvelope(envelope diskEnvelope, reference Reference, aead cipher.AEAD) bool {
	return envelope.Version == formatVersion && envelope.Reference == reference && len(envelope.Nonce) == aead.NonceSize() &&
		len(envelope.Ciphertext) >= aead.Overhead()
}

func plaintextMatches(plaintext []byte, reference Reference) bool {
	digest := sha256.Sum256(plaintext)
	return hex.EncodeToString(digest[:]) == reference.Digest && len(plaintext) == reference.Size
}

func (s *Store) sweepLocked(now time.Time) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, errors.New("scan sealed payload directory")
	}
	removed := 0
	for _, entry := range entries {
		path, remove := s.sweepCandidate(entry, now)
		if !remove {
			continue
		}
		if os.Remove(path) == nil {
			removed++
		}
	}
	return removed, nil
}

func (s *Store) sweepCandidate(entry os.DirEntry, now time.Time) (string, bool) {
	if entry.IsDir() {
		return "", false
	}
	name := entry.Name()
	path := filepath.Join(s.dir, name)
	if strings.HasSuffix(name, ".bin.consuming") {
		return path, true
	}
	if !strings.HasSuffix(name, ".bin") {
		return "", false
	}
	envelope, err := readDiskEnvelope(path)
	return path, err != nil || !s.validStoredEnvelope(envelope, name) || now.Unix() >= envelope.Reference.ExpiresAt
}

func (s *Store) validStoredEnvelope(envelope diskEnvelope, name string) bool {
	if envelope.Version != formatVersion || validateReference(envelope.Reference) != nil || name != envelope.Reference.ID+".bin" {
		return false
	}
	if !envelope.Consumed {
		return len(envelope.Nonce) == s.aead.NonceSize() && len(envelope.Ciphertext) >= s.aead.Overhead()
	}
	plaintext, err := s.aead.Open(nil, envelope.Nonce, envelope.Ciphertext, consumedAssociatedData(envelope.Reference))
	return err == nil && len(plaintext) == 0
}

func (s *Store) findRequestLocked(owner, purpose, requestKey, digest string, size int) (Reference, bool, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return Reference{}, false, errors.New("scan sealed payload directory")
	}
	for _, entry := range entries {
		reference, ok := s.requestReference(entry)
		if !ok || !sameRequest(reference, owner, purpose, requestKey) {
			continue
		}
		if !samePayload(reference, digest, size) {
			return Reference{}, false, errors.New("sealed payload idempotency conflict")
		}
		return reference, true, nil
	}
	return Reference{}, false, nil
}

func (s *Store) requestReference(entry os.DirEntry) (Reference, bool) {
	path, ok := s.storedPayloadPath(entry)
	if !ok {
		return Reference{}, false
	}
	envelope, err := readDiskEnvelope(path)
	if err != nil || !s.validStoredEnvelope(envelope, entry.Name()) {
		return Reference{}, false
	}
	return envelope.Reference, true
}

func (s *Store) storedPayloadPath(entry os.DirEntry) (string, bool) {
	return filepath.Join(s.dir, entry.Name()), !entry.IsDir() && strings.HasSuffix(entry.Name(), ".bin")
}

func sameRequest(reference Reference, owner, purpose, requestKey string) bool {
	return reference.Owner == owner && reference.Purpose == purpose && reference.RequestKey == requestKey
}

func samePayload(reference Reference, digest string, size int) bool {
	return reference.Digest == digest && reference.Size == size
}

func (s *Store) checkQuotaLocked(additionalBytes int64) error {
	count, total, err := s.storedUsage()
	if err != nil {
		return err
	}
	if count >= maxStoredFiles || additionalBytes <= 0 || total+additionalBytes > maxStoredBytes {
		return errors.New("sealed payload quota exceeded")
	}
	return nil
}

func (s *Store) storedUsage() (int, int64, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, 0, errors.New("scan sealed payload directory")
	}
	count := 0
	var total int64
	for _, entry := range entries {
		_, ok := s.storedPayloadPath(entry)
		if !ok {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			return 0, 0, errors.New("inspect sealed payload quota")
		}
		count++
		total += info.Size()
	}
	return count, total, nil
}

func readDiskEnvelope(path string) (diskEnvelope, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- caller supplies a path discovered under the fixed store directory.
	if err != nil {
		return diskEnvelope{}, fmt.Errorf("sealed payload envelope is unavailable: %w", err)
	}
	if len(data) == 0 || len(data) > maxFileBytes {
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
	if !validReferenceIdentity(reference) || !validReferenceBounds(reference) {
		return errors.New("sealed payload reference is invalid")
	}
	if _, err := hex.DecodeString(reference.Digest); err != nil {
		return fmt.Errorf("sealed payload reference is invalid")
	}
	return nil
}

func validReferenceIdentity(reference Reference) bool {
	return referencePattern.MatchString(reference.ID) && ownerPattern.MatchString(reference.Owner) &&
		purposePattern.MatchString(reference.Purpose) && validRequestKey(reference.RequestKey)
}

func validReferenceBounds(reference Reference) bool {
	return len(reference.Digest) == sha256.Size*2 && reference.Size > 0 && reference.Size <= maxSecretBytes && reference.ExpiresAt > 0
}

func validRequestKey(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && !strings.ContainsAny(value, "\t\r\n")
}

func associatedData(reference Reference) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d\x00%d", reference.ID, reference.Owner, reference.Purpose,
		reference.RequestKey, reference.Size, reference.ExpiresAt))
}

func consumedAssociatedData(reference Reference) []byte {
	return append(associatedData(reference), []byte("\x00consumed")...)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
