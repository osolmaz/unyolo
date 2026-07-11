// Package planstore persists immutable content-addressed provider plans.
package planstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

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
	digest := Digest(canonical)
	path := s.Path(digest)
	if current, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(bytes.TrimSpace(current), canonical) {
			return "", fmt.Errorf("%s plan digest collision", s.label)
		}
		return digest, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read %s plan: %w", s.label, err)
	}
	if err := store.WriteFileAtomic(path, append(append([]byte(nil), canonical...), '\n'), 0o600); err != nil {
		return "", err
	}
	return digest, nil
}

func (s *Store) Get(digest string) ([]byte, error) {
	if s == nil || !ValidDigest(digest) {
		return nil, errors.New("plan digest is invalid")
	}
	data, err := os.ReadFile(s.Path(digest))
	if err != nil {
		return nil, fmt.Errorf("read %s plan: %w", s.label, err)
	}
	canonical := bytes.TrimSpace(data)
	if Digest(canonical) != digest {
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
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		digest := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidDigest(digest) || referenced[digest] {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return removed, err
		}
		if !info.ModTime().Before(olderThan) {
			continue
		}
		if err := os.Remove(filepath.Join(s.directory, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

func (s *Store) Path(digest string) string { return filepath.Join(s.directory, digest+".json") }

func Digest(canonical []byte) string {
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:])
}

func ValidDigest(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
