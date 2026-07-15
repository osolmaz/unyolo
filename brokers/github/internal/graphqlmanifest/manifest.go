// Package graphqlmanifest owns reviewed persisted GitHub GraphQL documents.
package graphqlmanifest

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/upstream"
)

type Document struct {
	CatalogOperation   string         `json:"catalog_operation"`
	RootType           string         `json:"root_type"`
	RootField          string         `json:"root_field"`
	OperationName      string         `json:"operation_name"`
	Document           string         `json:"document"`
	SHA256             string         `json:"sha256"`
	VariableSchema     map[string]any `json:"variable_schema"`
	ResponseProjection []string       `json:"response_projection"`
	ExpectedCost       int            `json:"expected_cost"`
	CredentialKind     string         `json:"credential_kind"`
}

type Manifest struct {
	Version           int        `json:"version"`
	SchemaFingerprint string     `json:"schema_fingerprint"`
	Documents         []Document `json:"documents"`
}

//go:embed manifest.json
var raw []byte
var once sync.Once
var loaded Manifest
var loadErr error
var documentsByOperation map[string]Document

func All() ([]Document, error) { once.Do(load); return slices.Clone(loaded.Documents), loadErr }

func load() {
	if err := json.Unmarshal(raw, &loaded); err != nil {
		loadErr = err
		return
	}
	if err := validateManifestHeader(loaded); err != nil {
		loadErr = err
		return
	}
	rootFields, err := loadPinnedRootFields(loaded)
	if err != nil {
		loadErr = err
		return
	}
	loadErr = indexDocuments(loaded.Documents, rootFields)
}

func validateManifestHeader(manifest Manifest) error {
	if manifest.Version != 1 || len(manifest.Documents) != 284 {
		return errors.New("GitHub GraphQL manifest count drifted")
	}
	return nil
}

func loadPinnedRootFields(manifest Manifest) (map[string]bool, error) {
	schema, err := upstream.Read("graphql-introspection-2026-07-14.json")
	if err != nil {
		return nil, err
	}
	if !schemaFingerprintMatches(manifest, schema) {
		return nil, errors.New("GitHub GraphQL schema fingerprint drifted")
	}
	return pinnedRootFields(schema)
}

func schemaFingerprintMatches(manifest Manifest, schema []byte) bool {
	digest := sha256.Sum256(schema)
	return manifest.SchemaFingerprint == "sha256:"+hex.EncodeToString(digest[:])
}

func indexDocuments(documents []Document, rootFields map[string]bool) error {
	previous := ""
	documentsByOperation = make(map[string]Document, len(documents))
	for _, document := range documents {
		if document.CatalogOperation <= previous {
			return errors.New("GitHub GraphQL manifest is duplicated or unsorted")
		}
		previous = document.CatalogOperation
		if err := validateDocument(document, rootFields); err != nil {
			return err
		}
		documentsByOperation[document.CatalogOperation] = document
	}
	return nil
}

func validateDocument(document Document, rootFields map[string]bool) error {
	if !validDocumentMetadata(document) {
		return errors.New("GitHub GraphQL manifest is duplicated or unsorted")
	}
	if !rootFields[document.RootType+"."+document.RootField] {
		return fmt.Errorf("GraphQL document %q is absent from the pinned schema", document.CatalogOperation)
	}
	if descriptor, found := opcatalog.ByName(document.CatalogOperation); !found || descriptor.ExecutorKind != "persisted-graphql" {
		return fmt.Errorf("GraphQL document %q is not cataloged", document.CatalogOperation)
	}
	if !safeDocumentBody(document) {
		return fmt.Errorf("GraphQL document %q is unsafe", document.CatalogOperation)
	}
	if document.VariableSchema["additionalProperties"] != false {
		return fmt.Errorf("GraphQL variables for %q are open", document.CatalogOperation)
	}
	return nil
}

func validDocumentMetadata(document Document) bool {
	return document.RootField != "" && document.OperationName != "" && document.ExpectedCost >= 1 &&
		document.ExpectedCost <= 100 && document.CredentialKind != ""
}

func safeDocumentBody(document Document) bool {
	documentDigest := sha256.Sum256([]byte(document.Document))
	operationCount := strings.Count(document.Document, "query ") + strings.Count(document.Document, "mutation ")
	return hex.EncodeToString(documentDigest[:]) == document.SHA256 && !strings.Contains(document.Document, "__schema") &&
		!strings.Contains(document.Document, "__type(") && !strings.Contains(document.Document, "@") &&
		strings.Count(document.Document, "{") == strings.Count(document.Document, "}") && operationCount == 1
}

func pinnedRootFields(raw []byte) (map[string]bool, error) {
	var response struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, err
	}
	result := map[string]bool{}
	for _, typ := range response.Data.Schema.Types {
		root := ""
		switch typ.Name {
		case "Query":
			root = "query"
		case "Mutation":
			root = "mutation"
		}
		if root == "" {
			continue
		}
		for _, field := range typ.Fields {
			result[root+"."+field.Name] = true
		}
	}
	return result, nil
}

func ByOperation(name string) (Document, bool) {
	_, err := All()
	if err != nil {
		return Document{}, false
	}
	value, found := documentsByOperation[name]
	return value, found
}

func Validate() error { _, err := All(); return err }
