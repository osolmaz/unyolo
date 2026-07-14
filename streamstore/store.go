// Package streamstore persists bounded, short-lived provider byte streams in
// private files without loading them into memory or SQLite.
package streamstore

import (
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
)

var idPattern = regexp.MustCompile(`^stream_[A-Za-z0-9_-]{24}$`)

type Reference struct {
	ID         string `json:"id"`
	Owner      string `json:"owner"`
	Purpose    string `json:"purpose"`
	RequestKey string `json:"request_key"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	MediaType  string `json:"media_type"`
	ExpiresAt  int64  `json:"expires_at"`
}

type Store struct {
	dir string
	mu  sync.Mutex
	now func() time.Time
}

func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("stream state directory is required")
	}
	dir := filepath.Join(stateDir, "streams")
	if err := os.MkdirAll(dir, 0o700); err != nil || os.Chmod(dir, 0o700) != nil {
		return nil, errors.New("secure stream directory")
	}
	return &Store{dir: dir, now: time.Now}, nil
}

func (s *Store) Put(owner, purpose, requestKey, mediaType string, source io.Reader, limit int64, expires time.Time) (Reference, error) {
	if s == nil || source == nil || owner == "" || purpose == "" || requestKey == "" || mediaType == "" || limit <= 0 || !expires.After(s.now()) {
		return Reference{}, errors.New("stream metadata is invalid")
	}
	id, err := newID()
	if err != nil {
		return Reference{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.OpenFile(s.dataPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- random ID under private state.
	if err != nil {
		return Reference{}, errors.New("create stream")
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, limit+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size <= 0 || size > limit {
		_ = os.Remove(s.dataPath(id))
		return Reference{}, errors.New("stream exceeds its bounded size")
	}
	reference := Reference{ID: id, Owner: owner, Purpose: purpose, RequestKey: requestKey, Digest: hex.EncodeToString(hash.Sum(nil)),
		Size: size, MediaType: mediaType, ExpiresAt: expires.UTC().Unix()}
	encoded, _ := json.Marshal(reference)
	if err := writeMetadata(s.metaPath(id), encoded); err != nil {
		_ = os.Remove(s.dataPath(id))
		return Reference{}, errors.New("write stream metadata")
	}
	return reference, nil
}

func (s *Store) Validate(reference Reference) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.validateLocked(reference)
	return err
}

func (s *Store) OpenStream(reference Reference) (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.validateLocked(reference); err != nil {
		return nil, err
	}
	file, err := os.Open(s.dataPath(reference.ID)) // #nosec G304 -- validated ID under private state.
	if err != nil {
		return nil, errors.New("stream is unavailable")
	}
	if err := verifyFile(file, reference); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func (s *Store) Consume(owner, id string) (*os.File, Reference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reference, err := s.loadLocked(id)
	if err != nil || reference.Owner != owner {
		return nil, Reference{}, errors.New("stream is unavailable")
	}
	if _, err := s.validateLocked(reference); err != nil {
		return nil, Reference{}, err
	}
	file, err := os.Open(s.dataPath(id)) // #nosec G304 -- validated ID under private state.
	if err != nil {
		return nil, Reference{}, errors.New("stream is unavailable")
	}
	if err := verifyFile(file, reference); err != nil {
		_ = file.Close()
		return nil, Reference{}, err
	}
	if os.Remove(s.metaPath(id)) != nil || os.Remove(s.dataPath(id)) != nil {
		_ = file.Close()
		return nil, Reference{}, errors.New("consume stream")
	}
	return file, reference, nil
}

func (s *Store) Delete(reference Reference) error {
	if !idPattern.MatchString(reference.ID) {
		return errors.New("stream reference is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, path := range []string{s.metaPath(reference.ID), s.dataPath(reference.ID)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return errors.New("delete stream")
		}
	}
	return nil
}

func (s *Store) SweepExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, errors.New("inspect streams")
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		id := entry.Name()[:len(entry.Name())-len(".json")]
		reference, loadErr := s.loadLocked(id)
		if loadErr == nil && now.Unix() < reference.ExpiresAt {
			continue
		}
		_ = os.Remove(s.metaPath(id))
		_ = os.Remove(s.dataPath(id))
		removed++
	}
	return removed, nil
}

func (s *Store) validateLocked(reference Reference) (Reference, error) {
	stored, err := s.loadLocked(reference.ID)
	if err != nil || stored != reference || s.now().Unix() >= reference.ExpiresAt {
		return Reference{}, errors.New("stream reference is invalid")
	}
	info, err := os.Lstat(s.dataPath(reference.ID))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() != reference.Size {
		return Reference{}, errors.New("stream is unavailable")
	}
	return stored, nil
}

func (s *Store) loadLocked(id string) (Reference, error) {
	if !idPattern.MatchString(id) {
		return Reference{}, errors.New("stream reference is invalid")
	}
	data, err := os.ReadFile(s.metaPath(id)) // #nosec G304 -- validated ID under private state.
	var reference Reference
	if err != nil || len(data) > 4096 || json.Unmarshal(data, &reference) != nil || reference.ID != id || reference.Size <= 0 {
		return Reference{}, errors.New("stream is unavailable")
	}
	return reference, nil
}

func (s *Store) dataPath(id string) string { return filepath.Join(s.dir, id+".bin") }
func (s *Store) metaPath(id string) string { return filepath.Join(s.dir, id+".json") }

func newID() (string, error) {
	var data [18]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		return "", fmt.Errorf("generate stream id: %w", err)
	}
	return "stream_" + base64.RawURLEncoding.EncodeToString(data[:]), nil
}

func verifyFile(file *os.File, reference Reference) error {
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil || size != reference.Size || hex.EncodeToString(hash.Sum(nil)) != reference.Digest {
		return errors.New("stream integrity validation failed")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return errors.New("rewind stream")
	}
	return nil
}

func writeMetadata(path string, data []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".stream-metadata-*")
	if err != nil {
		return errors.New("create stream metadata")
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if file.Chmod(0o600) != nil {
		_ = file.Close()
		return errors.New("secure stream metadata")
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write stream metadata")
	}
	if file.Sync() != nil {
		_ = file.Close()
		return errors.New("write stream metadata")
	}
	if file.Close() != nil {
		return errors.New("write stream metadata")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("commit stream metadata")
	}
	return nil
}
