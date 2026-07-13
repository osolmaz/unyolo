// Package credentialstore persists generated provider credentials in named,
// broker-owned encrypted slots. It intentionally exposes no HTTP retrieval API.
package credentialstore

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
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/securefile"
)

const (
	keySize             = 32
	maxCredentialBytes  = 1 << 20
	credentialFileMode  = 0o600
	credentialDirectory = 0o700
)

var (
	slotPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
	kindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
)

type Metadata struct {
	Slot      string    `json:"slot"`
	Kind      string    `json:"kind"`
	Digest    string    `json:"digest"`
	Size      int       `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

type encryptedRecord struct {
	Metadata
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type Store struct {
	dir  string
	aead cipher.AEAD
	mu   sync.Mutex
	now  func() time.Time
}

// Exists reports whether an encrypted credential slot exists. It does not
// decrypt the slot or expose credential metadata.
func (s *Store) Exists(slot string) bool {
	if s == nil || !slotPattern.MatchString(slot) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Lstat(s.path(slot))
	return err == nil && info.Mode().IsRegular()
}

// Delete immediately removes an encrypted credential slot. Deletion is
// idempotent so revocation webhooks can be replayed safely.
func (s *Store) Delete(slot string) error {
	if s == nil || !slotPattern.MatchString(slot) {
		return errors.New("credential slot is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := os.Remove(s.path(slot))
	if err != nil && !os.IsNotExist(err) {
		return errors.New("delete credential slot")
	}
	return nil
}

func ValidSlot(value string) bool { return slotPattern.MatchString(value) }

func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("credential store state directory is required")
	}
	dir := filepath.Join(stateDir, "credential-slots")
	if err := os.MkdirAll(dir, credentialDirectory); err != nil || os.Chmod(dir, credentialDirectory) != nil {
		return nil, errors.New("secure credential slot directory")
	}
	key, err := loadOrCreateKey(filepath.Join(stateDir, "credential-slots.key"))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("initialize credential slot cipher")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.New("initialize credential slot cipher")
	}
	return &Store{dir: dir, aead: aead, now: time.Now}, nil
}

func (s *Store) Put(slot, kind string, plaintext []byte) (Metadata, error) {
	if s == nil || s.aead == nil || !slotPattern.MatchString(slot) || !kindPattern.MatchString(kind) || len(plaintext) == 0 || len(plaintext) > maxCredentialBytes {
		return Metadata{}, errors.New("credential slot value is invalid")
	}
	digest := sha256.Sum256(plaintext)
	metadata := Metadata{Slot: slot, Kind: kind, Digest: hex.EncodeToString(digest[:]), Size: len(plaintext), UpdatedAt: s.now().UTC()}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Metadata{}, errors.New("generate credential slot nonce")
	}
	ciphertext := s.aead.Seal(nil, nonce, plaintext, associatedData(metadata))
	record := encryptedRecord{Metadata: metadata, Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext)}
	encoded, err := json.Marshal(record)
	if err != nil {
		return Metadata{}, errors.New("encode credential slot")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := atomicWrite(s.path(slot), encoded); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}

//nolint:cyclop // Credential integrity checks are explicit and tracked by the exact HF CRAP baseline.
func (s *Store) Get(slot, kind string) ([]byte, Metadata, error) {
	if s == nil || s.aead == nil || !slotPattern.MatchString(slot) || !kindPattern.MatchString(kind) {
		return nil, Metadata{}, errors.New("credential slot is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path(slot)) // #nosec G304 -- path is a digest under the private store directory.
	if err != nil || len(data) > 2*maxCredentialBytes {
		return nil, Metadata{}, errors.New("credential slot is unavailable")
	}
	var record encryptedRecord
	if json.Unmarshal(data, &record) != nil || record.Slot != slot || record.Kind != kind || record.Size <= 0 || record.Size > maxCredentialBytes {
		return nil, Metadata{}, errors.New("credential slot is invalid")
	}
	nonce, nonceErr := base64.RawStdEncoding.DecodeString(record.Nonce)
	ciphertext, ciphertextErr := base64.RawStdEncoding.DecodeString(record.Ciphertext)
	if nonceErr != nil || ciphertextErr != nil || len(nonce) != s.aead.NonceSize() {
		return nil, Metadata{}, errors.New("credential slot is invalid")
	}
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, associatedData(record.Metadata))
	if err != nil || len(plaintext) != record.Size {
		return nil, Metadata{}, errors.New("credential slot is invalid")
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != record.Digest {
		zero(plaintext)
		return nil, Metadata{}, errors.New("credential slot is invalid")
	}
	return plaintext, record.Metadata, nil
}

func (s *Store) path(slot string) string {
	digest := sha256.Sum256([]byte(slot))
	return filepath.Join(s.dir, hex.EncodeToString(digest[:])+".json")
}

func associatedData(metadata Metadata) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", metadata.Slot, metadata.Kind, metadata.Digest, metadata.Size, metadata.UpdatedAt.UTC().Format(time.RFC3339Nano)))
}

func loadOrCreateKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path) // #nosec G304 -- fixed path under the configured state directory.
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || len(key) != keySize {
			return nil, errors.New("credential slot key is invalid")
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, errors.New("read credential slot key")
	}
	key = make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, errors.New("generate credential slot key")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, credentialFileMode) // #nosec G304 -- fixed installation-owned key path.
	if err != nil {
		return nil, errors.New("create credential slot key")
	}
	if err := securefile.WriteAndSync(file, key, "credential slot"); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

func atomicWrite(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".credential-slot-*")
	if err != nil {
		return errors.New("create credential slot")
	}
	temporary := file.Name()
	if err := file.Chmod(credentialFileMode); err != nil {
		_ = file.Close()
		_ = os.Remove(temporary)
		return errors.New("secure credential slot")
	}
	if err := securefile.WriteAndSync(file, data, "credential slot"); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return errors.New("replace credential slot")
	}
	return nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
