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
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/osolmaz/brokerkit/internal/securefile"
)

var idPattern = regexp.MustCompile(`^stream_[A-Za-z0-9_-]{24}$`)

const (
	maxStoredFiles = 64
	maxStoredBytes = int64(1 << 30)
)

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

type replayMarker struct {
	Reference   Reference `json:"reference"`
	RetainUntil int64     `json:"retain_until"`
}

type Store struct {
	dir      string
	mu       sync.Mutex
	now      func() time.Time
	maxFiles int
	maxBytes int64
}

func Open(stateDir string) (*Store, error) {
	if stateDir == "" {
		return nil, errors.New("stream state directory is required")
	}
	dir := filepath.Join(stateDir, "streams")
	// #nosec G302 -- this is a directory and 0700 is the least-permissive usable mode.
	if err := os.MkdirAll(dir, 0o700); err != nil || os.Chmod(dir, 0o700) != nil {
		return nil, errors.New("secure stream directory")
	}
	return &Store{dir: dir, now: time.Now, maxFiles: maxStoredFiles, maxBytes: maxStoredBytes}, nil
}

func (s *Store) Put(owner, purpose, requestKey, mediaType string, source io.Reader, limit int64, expires time.Time) (Reference, error) {
	if !validPut(s, owner, purpose, requestKey, mediaType, source, limit, expires) {
		return Reference{}, errors.New("stream metadata is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.putLocked(owner, purpose, requestKey, mediaType, source, limit, expires)
}

func (s *Store) putLocked(owner, purpose, requestKey, mediaType string, source io.Reader, limit int64, expires time.Time) (Reference, error) {
	if _, err := s.sweepExpiredLocked(s.now()); err != nil {
		return Reference{}, err
	}
	if existing, found, err := s.findRequestLocked(owner, purpose, requestKey); err != nil {
		return Reference{}, err
	} else if found {
		return replayStream(existing, mediaType, source, limit)
	}
	if err := s.checkQuotaLocked(limit); err != nil {
		return Reference{}, err
	}
	return s.createLocked(owner, purpose, requestKey, mediaType, source, limit, expires)
}

func replayStream(existing Reference, mediaType string, source io.Reader, limit int64) (Reference, error) {
	size, digest, err := digestStream(source, limit)
	if err != nil || existing.Digest != digest || existing.Size != size || existing.MediaType != mediaType {
		return Reference{}, errors.New("stream idempotency conflict")
	}
	return existing, nil
}

func (s *Store) createLocked(owner, purpose, requestKey, mediaType string, source io.Reader, limit int64, expires time.Time) (Reference, error) {
	id, err := newID()
	if err != nil {
		return Reference{}, err
	}
	size, digest, err := s.writeStream(id, source, limit)
	if err != nil {
		return Reference{}, err
	}
	reference := Reference{ID: id, Owner: owner, Purpose: purpose, RequestKey: requestKey, Digest: digest,
		Size: size, MediaType: mediaType, ExpiresAt: expires.UTC().Unix()}
	if err := s.writeReference(reference); err != nil {
		_ = os.Remove(s.dataPath(id))
		return Reference{}, err
	}
	return reference, nil
}

func digestStream(source io.Reader, limit int64) (int64, string, error) {
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(source, limit+1))
	if err != nil || size <= 0 || size > limit {
		return 0, "", errors.New("stream exceeds its bounded size")
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

func validPut(store *Store, owner, purpose, requestKey, mediaType string, source io.Reader, limit int64, expires time.Time) bool {
	if store == nil || source == nil {
		return false
	}
	return !slices.Contains([]string{owner, purpose, requestKey, mediaType}, "") && limit > 0 && expires.After(store.now())
}

func (s *Store) writeStream(id string, source io.Reader, limit int64) (int64, string, error) {
	file, err := os.OpenFile(s.dataPath(id), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- random ID under private state.
	if err != nil {
		return 0, "", errors.New("create stream")
	}
	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(source, limit+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || size <= 0 || size > limit {
		_ = os.Remove(s.dataPath(id))
		return 0, "", errors.New("stream exceeds its bounded size")
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}

func (s *Store) writeReference(reference Reference) error {
	encoded, _ := json.Marshal(reference)
	if err := writeMetadata(s.metaPath(reference.ID), encoded); err != nil {
		return errors.New("write stream metadata")
	}
	return nil
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
	return s.openVerified(reference)
}

func (s *Store) Consume(owner, id string) (*os.File, Reference, error) {
	file, reference, err := s.OpenOwned(owner, id)
	if err != nil {
		return nil, Reference{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.removeConsumed(id); err != nil {
		_ = file.Close()
		return nil, Reference{}, err
	}
	return file, reference, nil
}

// OpenOwned opens a verified stream for its owner without consuming it. The
// caller deletes the stream only after the complete response is delivered.
func (s *Store) OpenOwned(owner, id string) (*os.File, Reference, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reference, err := s.loadLocked(id)
	if err != nil || reference.Owner != owner {
		return nil, Reference{}, errors.New("stream is unavailable")
	}
	if _, err := s.validateLocked(reference); err != nil {
		return nil, Reference{}, err
	}
	file, err := s.openVerified(reference)
	if err != nil {
		return nil, Reference{}, err
	}
	return file, reference, nil
}

func (s *Store) openVerified(reference Reference) (*os.File, error) {
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

func (s *Store) removeConsumed(id string) error {
	if os.Remove(s.metaPath(id)) != nil || os.Remove(s.dataPath(id)) != nil {
		return errors.New("consume stream")
	}
	return nil
}

func (s *Store) Delete(reference Reference) error {
	if !idPattern.MatchString(reference.ID) {
		return errors.New("stream reference is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return removeFiles([]string{s.metaPath(reference.ID), s.dataPath(reference.ID), s.replayPath(reference.ID)}, "delete stream")
}

// Retire removes stream bytes while retaining enough metadata to replay the
// original upload request for the caller's idempotency window.
func (s *Store) Retire(reference Reference, retainUntil time.Time) error {
	if !idPattern.MatchString(reference.ID) || !retainUntil.After(s.now()) {
		return errors.New("stream retirement is invalid")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retireLocked(reference, retainUntil)
}

func (s *Store) retireLocked(reference Reference, retainUntil time.Time) error {
	if replayed, err := s.retirementReplay(reference); replayed || err != nil {
		return err
	}
	stored, err := s.loadLocked(reference.ID)
	if err != nil || stored != reference {
		return errors.New("stream reference is invalid")
	}
	marker := replayMarker{Reference: reference, RetainUntil: retainUntil.UTC().Unix()}
	encoded, _ := json.Marshal(marker)
	if err := writeMetadata(s.replayPath(reference.ID), encoded); err != nil {
		return errors.New("write stream replay metadata")
	}
	return removeFiles([]string{s.metaPath(reference.ID), s.dataPath(reference.ID)}, "retire stream")
}

func (s *Store) retirementReplay(reference Reference) (bool, error) {
	if _, err := os.Lstat(s.replayPath(reference.ID)); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return true, errors.New("inspect stream replay metadata")
	}
	marker, err := s.loadReplayLocked(reference.ID)
	if err != nil {
		return true, err
	}
	if marker.Reference != reference {
		return true, errors.New("stream retirement conflicts with existing replay metadata")
	}
	return true, nil
}

func removeFiles(paths []string, noun string) error {
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return errors.New(noun)
		}
	}
	return nil
}

func (s *Store) SweepExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepExpiredLocked(now)
}

func (s *Store) sweepExpiredLocked(now time.Time) (int, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0, errors.New("inspect streams")
	}
	removed := 0
	for _, entry := range entries {
		if s.sweepEntryLocked(entry, now) {
			removed++
		}
	}
	return removed, nil
}

func (s *Store) sweepEntryLocked(entry os.DirEntry, now time.Time) bool {
	extension := filepath.Ext(entry.Name())
	id, ok := streamEntryID(entry, extension)
	if !ok || !streamMetadataExtension(extension) {
		return false
	}
	expiresAt := s.entryExpiryLocked(id, extension)
	if now.Unix() < expiresAt {
		return false
	}
	s.removeExpiredEntry(id, entry.Name(), extension)
	return true
}

func streamMetadataExtension(extension string) bool {
	return extension == ".json" || extension == ".replay"
}

func (s *Store) removeExpiredEntry(id, name, extension string) {
	_ = os.Remove(filepath.Join(s.dir, name))
	if extension == ".json" {
		_ = os.Remove(s.dataPath(id))
	}
}

func (s *Store) entryExpiryLocked(id, extension string) int64 {
	if extension == ".json" {
		if reference, err := s.loadLocked(id); err == nil {
			return reference.ExpiresAt
		}
		return 0
	}
	if marker, err := s.loadReplayLocked(id); err == nil {
		return marker.RetainUntil
	}
	return 0
}

func (s *Store) findRequestLocked(owner, purpose, requestKey string) (Reference, bool, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return Reference{}, false, errors.New("inspect stream idempotency")
	}
	for _, entry := range entries {
		if reference, ok := s.referenceForEntryLocked(entry); ok && sameStreamRequest(reference, owner, purpose, requestKey) {
			return reference, true, nil
		}
	}
	return Reference{}, false, nil
}

func (s *Store) referenceForEntryLocked(entry os.DirEntry) (Reference, bool) {
	if id, ok := streamEntryID(entry, ".json"); ok {
		reference, err := s.loadLocked(id)
		return reference, err == nil
	}
	if id, ok := streamEntryID(entry, ".replay"); ok {
		marker, err := s.loadReplayLocked(id)
		return marker.Reference, err == nil
	}
	return Reference{}, false
}

func (s *Store) checkQuotaLocked(additionalBytes int64) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return errors.New("inspect stream quota")
	}
	count := 0
	var total int64
	for _, entry := range entries {
		_, ok := streamEntryID(entry, ".bin")
		if !ok {
			continue
		}
		size, statErr := streamEntrySize(entry)
		if statErr != nil {
			return errors.New("inspect stream quota")
		}
		count++
		total += size
	}
	if !withinStreamQuota(count, total, additionalBytes, s.maxFiles, s.maxBytes) {
		return errors.New("stream quota exceeded")
	}
	return nil
}

func withinStreamQuota(count int, total, additionalBytes int64, maxFiles int, maxBytes int64) bool {
	return count < maxFiles && additionalBytes > 0 && additionalBytes <= maxBytes-total
}

func streamEntryID(entry os.DirEntry, extension string) (string, bool) {
	if entry.IsDir() || filepath.Ext(entry.Name()) != extension {
		return "", false
	}
	return strings.TrimSuffix(entry.Name(), extension), true
}

func sameStreamRequest(reference Reference, owner, purpose, requestKey string) bool {
	return reference.Owner == owner && reference.Purpose == purpose && reference.RequestKey == requestKey
}

func streamEntrySize(entry os.DirEntry) (int64, error) {
	info, err := entry.Info()
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *Store) validateLocked(reference Reference) (Reference, error) {
	stored, err := s.loadLocked(reference.ID)
	if err != nil || stored != reference || s.now().Unix() >= reference.ExpiresAt {
		return Reference{}, errors.New("stream reference is invalid")
	}
	info, err := os.Lstat(s.dataPath(reference.ID))
	if err != nil || !validStreamFile(info, reference) {
		return Reference{}, errors.New("stream is unavailable")
	}
	return stored, nil
}

func validStreamFile(info os.FileInfo, reference Reference) bool {
	return !slices.Contains([]bool{info.Mode().IsRegular(), info.Mode().Perm()&0o077 == 0, info.Size() == reference.Size}, false)
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

func (s *Store) loadReplayLocked(id string) (replayMarker, error) {
	if !idPattern.MatchString(id) {
		return replayMarker{}, errors.New("stream reference is invalid")
	}
	data, err := os.ReadFile(s.replayPath(id)) // #nosec G304 -- validated ID under private state.
	var marker replayMarker
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &marker) != nil || marker.Reference.ID != id || marker.Reference.Size <= 0 || marker.RetainUntil <= 0 {
		return replayMarker{}, errors.New("stream replay metadata is unavailable")
	}
	return marker, nil
}

func (s *Store) dataPath(id string) string   { return filepath.Join(s.dir, id+".bin") }
func (s *Store) metaPath(id string) string   { return filepath.Join(s.dir, id+".json") }
func (s *Store) replayPath(id string) string { return filepath.Join(s.dir, id+".replay") }

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
	return securefile.AtomicWrite(path, data, 0o600, "stream metadata")
}
