// Package upstream validates and exposes immutable official GitHub snapshots.
package upstream

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
)

//go:embed snapshots/* snapshots/webhooks/*
var snapshots embed.FS

type Artifact struct {
	Path              string `json:"path"`
	SourceURL         string `json:"source_url"`
	SourceCommit      string `json:"source_commit,omitempty"`
	SchemaFingerprint string `json:"schema_fingerprint,omitempty"`
	APIVersion        string `json:"api_version,omitempty"`
	SHA256            string `json:"sha256"`
	License           string `json:"license"`
	LicenseFile       string `json:"license_file"`
}

type Provenance struct {
	Version     int        `json:"version"`
	RetrievedAt string     `json:"retrieved_at"`
	Artifacts   []Artifact `json:"artifacts"`
}

func Read(name string) ([]byte, error) {
	if path.Clean(name) != name || name == "." || name == "" {
		return nil, errors.New("invalid upstream snapshot name")
	}
	return snapshots.ReadFile("snapshots/" + name)
}

func Metadata() (Provenance, error) {
	data, err := Read("provenance.json")
	if err != nil {
		return Provenance{}, err
	}
	var provenance Provenance
	if err := json.Unmarshal(data, &provenance); err != nil {
		return provenance, err
	}
	return provenance, nil
}

//nolint:cyclop // Every pinned artifact and license notice is verified in one audit pass.
func Validate() error {
	provenance, err := Metadata()
	if err != nil {
		return err
	}
	if provenance.Version != 1 || len(provenance.Artifacts) != 11 || provenance.RetrievedAt == "" {
		return errors.New("GitHub upstream provenance is incomplete")
	}
	seen := map[string]bool{}
	for _, artifact := range provenance.Artifacts {
		if artifact.Path == "" || artifact.SourceURL == "" || artifact.SHA256 == "" || artifact.License == "" || artifact.LicenseFile == "" || seen[artifact.Path] {
			return errors.New("GitHub upstream artifact metadata is invalid")
		}
		seen[artifact.Path] = true
		data, err := Read(artifact.Path)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != artifact.SHA256 {
			return fmt.Errorf("GitHub upstream snapshot %q digest drifted", artifact.Path)
		}
		if _, err := Read(artifact.LicenseFile); err != nil {
			return fmt.Errorf("GitHub upstream snapshot %q license notice: %w", artifact.Path, err)
		}
	}
	if !seen["rest-api-2026-03-10.json"] || !seen["graphql-introspection-2026-07-14.json"] || !seen["github-app-permissions-2026-03-10.json"] {
		return errors.New("required GitHub upstream snapshots are missing")
	}
	return nil
}

func ArtifactPaths() ([]string, error) {
	metadata, err := Metadata()
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(metadata.Artifacts))
	for _, artifact := range metadata.Artifacts {
		result = append(result, artifact.Path)
	}
	slices.Sort(result)
	return result, nil
}
