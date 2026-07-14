// Package upstreamdrift compares official GitHub metadata with reviewed snapshots.
package upstreamdrift

import "time"

const (
	CategoryAPIVersion     = "api-version"
	CategoryAuthentication = "authentication"
	CategoryDeprecation    = "deprecation"
	CategoryOperation      = "operation"
	CategoryPermission     = "permission"
	CategorySchema         = "schema"
)

// SnapshotSet contains the reviewed and current upstream capability inputs.
type SnapshotSet struct {
	REST        []byte
	GraphQL     []byte
	Permissions []byte
	APIVersions []string
	Sources     []Source
}

// Source records the immutable identity of one fetched upstream input.
type Source struct {
	Kind        string
	URL         string
	Commit      string
	APIVersion  string
	SHA256      string
	RetrievedAt time.Time
}

// Change is one structural difference between reviewed and current metadata.
type Change struct {
	Category string
	Kind     string
	Key      string
	Before   string
	After    string
}

// Report is a bounded, deterministic drift result.
type Report struct {
	RetrievedAt time.Time
	Sources     []Source
	Changes     []Change
}

// HasDrift reports whether the current metadata differs structurally.
func (r Report) HasDrift() bool { return len(r.Changes) != 0 }
