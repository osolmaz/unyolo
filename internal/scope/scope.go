// Package scope models the hand-edited scope.json file and decides which
// operations are allowed against which targets.
//
// The file is loaded once at startup; there is deliberately no API to
// read or change it at runtime. Parsing fails closed: unknown fields,
// malformed ids, and invalid modes all reject the whole file.
package scope

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

// RepoType is the Hub repository kind; it determines the upstream URL prefix.
type RepoType string

// Supported repository types.
const (
	TypeModel   RepoType = "model"
	TypeDataset RepoType = "dataset"
	TypeSpace   RepoType = "space"
)

// Mode is a target's standing access mode. There is intentionally no
// full-write mode; anything beyond append-only is a grant (level 4).
type Mode string

// Supported modes.
const (
	ModeReadOnly   Mode = "read-only"
	ModeAppendOnly Mode = "append-only"
)

// Repo is one in-scope git repository.
type Repo struct {
	Owner string
	Name  string
	Type  RepoType
	Mode  Mode
}

// Bucket is one in-scope bucket (enforced by the bucket proxy, M2).
type Bucket struct {
	Owner          string
	Name           string
	Mode           Mode
	SnapshotPrefix string
}

// Scope is the parsed, validated scope file.
type Scope struct {
	repos   map[string]Repo
	buckets map[string]Bucket
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type repoJSON struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Mode string `json:"mode"`
}

type bucketJSON struct {
	ID             string `json:"id"`
	Mode           string `json:"mode"`
	SnapshotPrefix string `json:"snapshot_prefix"`
}

type scopeJSON struct {
	Repos   []repoJSON   `json:"repos"`
	Buckets []bucketJSON `json:"buckets"`
}

// LoadFile reads and parses the scope file at path.
func LoadFile(path string) (Scope, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-configured path from the environment.
	if err != nil {
		return Scope{}, fmt.Errorf("read scope file: %w", err)
	}
	return Parse(data)
}

// Parse parses scope.json content, rejecting unknown fields.
func Parse(data []byte) (Scope, error) {
	raw, err := decodeScopeJSON(data)
	if err != nil {
		return Scope{}, err
	}
	return buildScope(raw)
}

func decodeScopeJSON(data []byte) (scopeJSON, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw scopeJSON
	if err := decoder.Decode(&raw); err != nil {
		return scopeJSON{}, fmt.Errorf("parse scope file: %w", err)
	}
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return scopeJSON{}, fmt.Errorf("parse scope file: trailing content")
	}
	return raw, nil
}

func buildScope(raw scopeJSON) (Scope, error) {
	scope := Scope{repos: map[string]Repo{}, buckets: map[string]Bucket{}}
	for _, entry := range raw.Repos {
		repo, err := parseRepo(entry)
		if err != nil {
			return Scope{}, err
		}
		key := repoKey(repo.Type, repo.Owner, repo.Name)
		if _, exists := scope.repos[key]; exists {
			return Scope{}, fmt.Errorf("duplicate repo %q", entry.ID)
		}
		scope.repos[key] = repo
	}
	for _, entry := range raw.Buckets {
		bucket, err := parseBucket(entry)
		if err != nil {
			return Scope{}, err
		}
		key := entry.ID
		if _, exists := scope.buckets[key]; exists {
			return Scope{}, fmt.Errorf("duplicate bucket %q", entry.ID)
		}
		scope.buckets[key] = bucket
	}
	return scope, nil
}

func parseRepo(entry repoJSON) (Repo, error) {
	owner, name, err := splitID(entry.ID)
	if err != nil {
		return Repo{}, fmt.Errorf("repo %q: %w", entry.ID, err)
	}
	repoType := RepoType(entry.Type)
	switch repoType {
	case TypeModel, TypeDataset, TypeSpace:
	default:
		return Repo{}, fmt.Errorf("repo %q: type must be model, dataset, or space", entry.ID)
	}
	mode, err := parseMode(entry.Mode)
	if err != nil {
		return Repo{}, fmt.Errorf("repo %q: %w", entry.ID, err)
	}
	return Repo{Owner: owner, Name: name, Type: repoType, Mode: mode}, nil
}

func parseBucket(entry bucketJSON) (Bucket, error) {
	owner, name, err := splitID(entry.ID)
	if err != nil {
		return Bucket{}, fmt.Errorf("bucket %q: %w", entry.ID, err)
	}
	mode, err := parseMode(entry.Mode)
	if err != nil {
		return Bucket{}, fmt.Errorf("bucket %q: %w", entry.ID, err)
	}
	prefix := entry.SnapshotPrefix
	if prefix == "" {
		prefix = "snapshots/"
	}
	if !strings.HasSuffix(prefix, "/") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
		return Bucket{}, fmt.Errorf("bucket %q: snapshot_prefix must be a relative prefix ending with /", entry.ID)
	}
	return Bucket{Owner: owner, Name: name, Mode: mode, SnapshotPrefix: prefix}, nil
}

func parseMode(value string) (Mode, error) {
	switch Mode(value) {
	case ModeReadOnly, ModeAppendOnly:
		return Mode(value), nil
	case "":
		return ModeAppendOnly, nil
	default:
		return "", fmt.Errorf("mode must be read-only or append-only, got %q", value)
	}
}

func splitID(id string) (owner, name string, err error) {
	owner, name, found := strings.Cut(id, "/")
	if !found || !namePattern.MatchString(owner) || !namePattern.MatchString(name) || strings.Contains(id, "..") {
		return "", "", fmt.Errorf("id must be owner/name with [A-Za-z0-9._-] segments")
	}
	return owner, name, nil
}

func repoKey(t RepoType, owner, name string) string {
	return string(t) + "/" + owner + "/" + name
}

// Repo returns the scope entry for (type, owner, name), if any.
func (s Scope) Repo(t RepoType, owner, name string) (Repo, bool) {
	repo, ok := s.repos[repoKey(t, owner, name)]
	return repo, ok
}

// Buckets returns all configured buckets (used by the bucket proxy, M2).
func (s Scope) Buckets() []Bucket {
	buckets := make([]Bucket, 0, len(s.buckets))
	for _, bucket := range s.buckets {
		buckets = append(buckets, bucket)
	}
	return buckets
}
