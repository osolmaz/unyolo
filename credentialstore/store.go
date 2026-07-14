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
	"slices"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/keyfile"
	"github.com/osolmaz/brokerkit/internal/securefile"
)

const (
	keySize             = 32
	maxCredentialBytes  = 1 << 20
	credentialFileMode  = 0o600
	credentialDirectory = 0o700
	namespaceDirectory  = "credential-namespaces"
)

var (
	slotPattern      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._-]{0,127}$`)
	kindPattern      = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	namespacePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
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

// NamespacePath returns the isolated state directory for a credential
// namespace. Namespaces use the same conservative vocabulary as credential
// kinds and cannot escape the broker state directory.
func NamespacePath(stateDir, namespace string) (string, error) {
	if stateDir == "" {
		return "", errors.New("credential store state directory is required")
	}
	if !namespacePattern.MatchString(namespace) {
		return "", errors.New("credential store namespace is invalid")
	}
	return filepath.Join(stateDir, namespaceDirectory, namespace), nil
}

// OpenNamespace opens an encrypted store whose keys and slots are isolated
// from every other namespace in the same broker state directory.
func OpenNamespace(stateDir, namespace string) (*Store, error) {
	root, err := NamespacePath(stateDir, namespace)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{filepath.Dir(root), root} {
		if err := secureStoreDirectory(path); err != nil {
			return nil, err
		}
	}
	return Open(root)
}

func secureStoreDirectory(path string) error {
	if err := os.MkdirAll(path, credentialDirectory); err != nil {
		return errors.New("create credential namespace directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("credential namespace directory is unsafe")
	}
	if err := os.Chmod(path, credentialDirectory); err != nil {
		return errors.New("secure credential namespace directory")
	}
	return nil
}

func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("credential store state directory is required")
	}
	dir := filepath.Join(stateDir, "credential-slots")
	if err := os.MkdirAll(dir, credentialDirectory); err != nil || os.Chmod(dir, credentialDirectory) != nil {
		return nil, errors.New("secure credential slot directory")
	}
	key, err := keyfile.LoadOrCreate(filepath.Join(stateDir, "credential-slots.key"), keySize, "credential slot", keyfile.Raw)
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
	if !validPut(s, slot, kind, plaintext) {
		return Metadata{}, errors.New("credential slot value is invalid")
	}
	digest := sha256.Sum256(plaintext)
	metadata := Metadata{Slot: slot, Kind: kind, Digest: hex.EncodeToString(digest[:]), Size: len(plaintext), UpdatedAt: s.now().UTC()}
	record, err := s.encrypt(metadata, plaintext)
	if err != nil {
		return Metadata{}, err
	}
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

func validPut(store *Store, slot, kind string, plaintext []byte) bool {
	return !slices.Contains([]bool{store != nil, store != nil && store.aead != nil, slotPattern.MatchString(slot), kindPattern.MatchString(kind),
		len(plaintext) > 0, len(plaintext) <= maxCredentialBytes}, false)
}

func (s *Store) encrypt(metadata Metadata, plaintext []byte) (encryptedRecord, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return encryptedRecord{}, errors.New("generate credential slot nonce")
	}
	ciphertext := s.aead.Seal(nil, nonce, plaintext, associatedData(metadata))
	return encryptedRecord{Metadata: metadata, Nonce: base64.RawStdEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawStdEncoding.EncodeToString(ciphertext)}, nil
}

func (s *Store) Get(slot, kind string) ([]byte, Metadata, error) {
	if !validGet(s, slot, kind) {
		return nil, Metadata{}, errors.New("credential slot is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.readRecord(slot, kind)
	if err != nil {
		return nil, Metadata{}, err
	}
	plaintext, err := s.decrypt(record)
	if err != nil {
		return nil, Metadata{}, err
	}
	return plaintext, record.Metadata, nil
}

func validGet(store *Store, slot, kind string) bool {
	return !slices.Contains([]bool{store != nil, store != nil && store.aead != nil, slotPattern.MatchString(slot), kindPattern.MatchString(kind)}, false)
}

func (s *Store) readRecord(slot, kind string) (encryptedRecord, error) {
	data, err := os.ReadFile(s.path(slot)) // #nosec G304 -- path is a digest under the private store directory.
	if err != nil || len(data) > 2*maxCredentialBytes {
		return encryptedRecord{}, errors.New("credential slot is unavailable")
	}
	var record encryptedRecord
	if json.Unmarshal(data, &record) != nil || !validRecord(record, slot, kind) {
		return encryptedRecord{}, errors.New("credential slot is invalid")
	}
	return record, nil
}

func validRecord(record encryptedRecord, slot, kind string) bool {
	return !slices.Contains([]bool{record.Slot == slot, record.Kind == kind, record.Size > 0, record.Size <= maxCredentialBytes}, false)
}

func (s *Store) decrypt(record encryptedRecord) ([]byte, error) {
	nonce, nonceErr := base64.RawStdEncoding.DecodeString(record.Nonce)
	ciphertext, ciphertextErr := base64.RawStdEncoding.DecodeString(record.Ciphertext)
	if nonceErr != nil || ciphertextErr != nil || len(nonce) != s.aead.NonceSize() {
		return nil, errors.New("credential slot is invalid")
	}
	plaintext, err := s.aead.Open(nil, nonce, ciphertext, associatedData(record.Metadata))
	if err != nil || len(plaintext) != record.Size {
		return nil, errors.New("credential slot is invalid")
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != record.Digest {
		zero(plaintext)
		return nil, errors.New("credential slot is invalid")
	}
	return plaintext, nil
}

func (s *Store) path(slot string) string {
	digest := sha256.Sum256([]byte(slot))
	return filepath.Join(s.dir, hex.EncodeToString(digest[:])+".json")
}

func associatedData(metadata Metadata) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%s", metadata.Slot, metadata.Kind, metadata.Digest, metadata.Size, metadata.UpdatedAt.UTC().Format(time.RFC3339Nano)))
}

func atomicWrite(path string, data []byte) error {
	return securefile.AtomicWrite(path, data, credentialFileMode, "credential slot")
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
