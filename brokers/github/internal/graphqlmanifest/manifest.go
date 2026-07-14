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

//nolint:cyclop // Persisted-document safety checks stay together for auditability.
func load() {
	if err := json.Unmarshal(raw, &loaded); err != nil {
		loadErr = err
		return
	}
	if loaded.Version != 1 || len(loaded.Documents) != 284 {
		loadErr = errors.New("GitHub GraphQL manifest count drifted")
		return
	}
	schema, err := upstream.Read("graphql-introspection-2026-07-14.json")
	if err != nil {
		loadErr = err
		return
	}
	digest := sha256.Sum256(schema)
	if loaded.SchemaFingerprint != "sha256:"+hex.EncodeToString(digest[:]) {
		loadErr = errors.New("GitHub GraphQL schema fingerprint drifted")
		return
	}
	rootFields, err := pinnedRootFields(schema)
	if err != nil {
		loadErr = err
		return
	}
	previous := ""
	documentsByOperation = make(map[string]Document, len(loaded.Documents))
	for _, document := range loaded.Documents {
		if document.CatalogOperation <= previous || document.RootField == "" || document.OperationName == "" || document.ExpectedCost < 1 || document.ExpectedCost > 100 || document.CredentialKind == "" {
			loadErr = errors.New("GitHub GraphQL manifest is duplicated or unsorted")
			return
		}
		previous = document.CatalogOperation
		if !rootFields[document.RootType+"."+document.RootField] {
			loadErr = fmt.Errorf("GraphQL document %q is absent from the pinned schema", document.CatalogOperation)
			return
		}
		if descriptor, found := opcatalog.ByName(document.CatalogOperation); !found || descriptor.ExecutorKind != "persisted-graphql" {
			loadErr = fmt.Errorf("GraphQL document %q is not cataloged", document.CatalogOperation)
			return
		}
		documentDigest := sha256.Sum256([]byte(document.Document))
		operationCount := strings.Count(document.Document, "query ") + strings.Count(document.Document, "mutation ")
		if hex.EncodeToString(documentDigest[:]) != document.SHA256 || strings.Contains(document.Document, "__schema") || strings.Contains(document.Document, "__type(") || strings.Contains(document.Document, "@") || strings.Count(document.Document, "{") != strings.Count(document.Document, "}") || operationCount != 1 {
			loadErr = fmt.Errorf("GraphQL document %q is unsafe", document.CatalogOperation)
			return
		}
		if document.VariableSchema["additionalProperties"] != false {
			loadErr = fmt.Errorf("GraphQL variables for %q are open", document.CatalogOperation)
			return
		}
		documentsByOperation[document.CatalogOperation] = document
	}
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
