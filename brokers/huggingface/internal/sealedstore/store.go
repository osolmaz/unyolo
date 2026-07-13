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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

const (
	keyBytes       = 32
	maxSecretBytes = 1 << 20
	formatVersion  = byte(1)
)

var referencePattern = regexp.MustCompile(`^sealed_[A-Za-z0-9_-]{24}$`)

type Reference struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
	Size   int    `json:"size"`
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
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, errors.New("secure sealed payload directory")
	}
	return &Store{dir: dir, aead: aead}, nil
}

func (s *Store) Put(plaintext []byte) (Reference, error) {
	if s == nil || s.aead == nil || len(plaintext) == 0 || len(plaintext) > maxSecretBytes {
		return Reference{}, errors.New("sealed payload is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 8 {
		reference, err := randomReference()
		if err != nil {
			return Reference{}, errors.New("generate sealed payload reference")
		}
		nonce := make([]byte, s.aead.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return Reference{}, errors.New("generate sealed payload nonce")
		}
		ciphertext := s.aead.Seal(nil, nonce, plaintext, []byte(reference))
		encoded := append([]byte{formatVersion}, nonce...)
		encoded = append(encoded, ciphertext...)
		path := s.path(reference)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return Reference{}, errors.New("create sealed payload")
		}
		writeErr := writeAndSync(file, encoded)
		if writeErr != nil {
			_ = os.Remove(path)
			return Reference{}, writeErr
		}
		digest := sha256.Sum256(plaintext)
		return Reference{ID: reference, Digest: hex.EncodeToString(digest[:]), Size: len(plaintext)}, nil
	}
	return Reference{}, errors.New("allocate sealed payload reference")
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
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from a validated random reference.
	if err != nil || len(data) < 1+s.aead.NonceSize()+s.aead.Overhead() || len(data) > maxSecretBytes+s.aead.Overhead()+s.aead.NonceSize()+1 {
		return nil, errors.New("sealed payload is unavailable")
	}
	if data[0] != formatVersion {
		return nil, errors.New("sealed payload format is unsupported")
	}
	nonceEnd := 1 + s.aead.NonceSize()
	plaintext, err := s.aead.Open(nil, data[1:nonceEnd], data[nonceEnd:], []byte(reference.ID))
	if err != nil {
		return nil, errors.New("sealed payload authentication failed")
	}
	digest := sha256.Sum256(plaintext)
	if hex.EncodeToString(digest[:]) != reference.Digest || len(plaintext) != reference.Size {
		return nil, errors.New("sealed payload binding failed")
	}
	return plaintext, nil
}

func (s *Store) path(reference string) string { return filepath.Join(s.dir, reference+".bin") }

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
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, errors.New("create sealed payload key")
	}
	if err := writeAndSync(file, []byte(base64.RawStdEncoding.EncodeToString(key))); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return key, nil
}

func writeAndSync(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write sealed payload")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync sealed payload")
	}
	if err := file.Close(); err != nil {
		return errors.New("close sealed payload")
	}
	return nil
}

func randomReference() (string, error) {
	data := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return "sealed_" + base64.RawURLEncoding.EncodeToString(data), nil
}

func validateReference(reference Reference) error {
	if !referencePattern.MatchString(reference.ID) || len(reference.Digest) != sha256.Size*2 || reference.Size <= 0 || reference.Size > maxSecretBytes {
		return errors.New("sealed payload reference is invalid")
	}
	if _, err := hex.DecodeString(reference.Digest); err != nil {
		return fmt.Errorf("sealed payload reference is invalid")
	}
	return nil
}
