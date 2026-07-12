// Package planstore persists immutable content-addressed provider plans.
package planstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/store"
)

type Store struct {
	directory string
	label     string
}

func New(directory string, label string) (*Store, error) {
	if strings.TrimSpace(directory) == "" || strings.TrimSpace(label) == "" {
		return nil, errors.New("plan store directory and label are required")
	}
	return &Store{directory: directory, label: label}, nil
}

func (s *Store) Put(canonical []byte) (string, error) {
	if s == nil || len(bytes.TrimSpace(canonical)) == 0 || !bytes.Equal(bytes.TrimSpace(canonical), canonical) {
		return "", errors.New("canonical plan bytes are required")
	}
	digest := plandigest.Digest(canonical)
	path := s.Path(digest)
	found, err := s.checkExisting(path, canonical)
	if err != nil {
		return "", err
	}
	if found {
		return digest, nil
	}
	if err := store.WriteFileAtomic(path, append(append([]byte(nil), canonical...), '\n'), 0o600); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *Store) checkExisting(path string, canonical []byte) (bool, error) {
	current, err := os.ReadFile(path) // #nosec G304 -- path is derived from a validated content digest under the configured plan directory.
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read %s plan: %w", s.label, err)
	}
	if !bytes.Equal(bytes.TrimSpace(current), canonical) {
		return false, fmt.Errorf("%s plan digest collision", s.label)
	}
	return true, nil
}

func (s *Store) Get(digest string) ([]byte, error) {
	if s == nil || !plandigest.Valid(digest) {
		return nil, errors.New("plan digest is invalid")
	}
	data, err := os.ReadFile(s.Path(digest))
	if err != nil {
		return nil, fmt.Errorf("read %s plan: %w", s.label, err)
	}
	canonical := bytes.TrimSpace(data)
	if plandigest.Digest(canonical) != digest {
		return nil, fmt.Errorf("%s plan content digest mismatch", s.label)
	}
	return append([]byte(nil), canonical...), nil
}

func (s *Store) CollectOrphans(referenced map[string]bool, olderThan time.Time) (int, error) {
	if s == nil {
		return 0, errors.New("plan store is unavailable")
	}
	entries, err := os.ReadDir(s.directory)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		wasRemoved, err := s.removeOrphan(entry, referenced, olderThan)
		if err != nil {
			return removed, err
		}
		if wasRemoved {
			removed++
		}
	}
	return removed, nil
}

func (s *Store) removeOrphan(entry os.DirEntry, referenced map[string]bool, olderThan time.Time) (bool, error) {
	if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
		return false, nil
	}
	digest := strings.TrimSuffix(entry.Name(), ".json")
	if !plandigest.Valid(digest) || referenced[digest] {
		return false, nil
	}
	info, err := entry.Info()
	if err != nil || !info.ModTime().Before(olderThan) {
		return false, err
	}
	err = os.Remove(filepath.Join(s.directory, entry.Name()))
	return err == nil, ignoreMissing(err)
}

func ignoreMissing(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s *Store) Path(digest string) string { return filepath.Join(s.directory, digest+".json") }
