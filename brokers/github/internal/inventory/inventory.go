// Package inventory owns exhaustive dispositions for pinned GitHub surfaces.
package inventory

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

const RESTCount = 1196
const GraphQLRootCount = 300

type RESTRow struct {
	UpstreamID          string            `json:"upstream_id"`
	Method              string            `json:"method"`
	Path                string            `json:"path"`
	Summary             string            `json:"summary"`
	Disposition         string            `json:"disposition"`
	CatalogOperations   []string          `json:"catalog_operations,omitempty"`
	DuplicateOf         string            `json:"duplicate_of,omitempty"`
	CredentialKind      string            `json:"credential_kind,omitempty"`
	RequiredCredential  string            `json:"required_credential,omitempty"`
	RequiredPermissions map[string]string `json:"required_github_permissions,omitempty"`
	Reason              string            `json:"reason,omitempty"`
	RiskClasses         []string          `json:"risk_classes,omitempty"`
	Reviewed            bool              `json:"reviewed"`
}

type GraphQLRow struct {
	RootType           string `json:"root_type"`
	Field              string `json:"field"`
	Deprecated         bool   `json:"deprecated"`
	Disposition        string `json:"disposition"`
	CatalogOperation   string `json:"catalog_operation,omitempty"`
	DuplicateOf        string `json:"duplicate_of,omitempty"`
	RequiredCredential string `json:"required_credential,omitempty"`
	Reason             string `json:"reason,omitempty"`
	PersistedDigest    string `json:"persisted_digest,omitempty"`
	Reviewed           bool   `json:"reviewed"`
}

//go:embed rest-coverage.json
var restRaw []byte

//go:embed graphql-coverage.json
var graphqlRaw []byte

//go:embed high-risk-review.json
var reviewRaw []byte

//go:embed overrides.json
var overridesRaw []byte

var once sync.Once
var restRows []RESTRow
var graphqlRows []GraphQLRow
var loadErr error

func AllREST() ([]RESTRow, error)       { load(); return slices.Clone(restRows), loadErr }
func AllGraphQL() ([]GraphQLRow, error) { load(); return slices.Clone(graphqlRows), loadErr }

func load() {
	once.Do(func() {
		if err := json.Unmarshal(restRaw, &restRows); err != nil {
			loadErr = err
			return
		}
		if err := json.Unmarshal(graphqlRaw, &graphqlRows); err != nil {
			loadErr = err
			return
		}
		loadErr = Validate(restRows, graphqlRows)
	})
}

func Validate(rest []RESTRow, graphql []GraphQLRow) error {
	if len(rest) != RESTCount || len(graphql) != GraphQLRootCount {
		return fmt.Errorf("GitHub inventory counts are %d REST/%d GraphQL", len(rest), len(graphql))
	}
	allowed := []string{"implemented", "protocol", "graphql", "internal", "operator-only", "local", "duplicate", "blocked-credential", "blocked-upstream"}
	if err := validateRESTRows(rest, allowed); err != nil {
		return err
	}
	if err := validateGraphQLRows(graphql, allowed); err != nil {
		return err
	}
	return validateReviewArtifacts()
}

func validateRESTRows(rest []RESTRow, allowed []string) error {
	seen := map[string]bool{}
	for _, row := range rest {
		key := row.Method + " " + row.Path
		if !validRESTRow(row, key, seen, allowed) {
			return fmt.Errorf("invalid REST coverage row %q", key)
		}
		seen[key] = true
		if err := validateRESTDisposition(row, key); err != nil {
			return err
		}
	}
	return nil
}

func validateRESTDisposition(row RESTRow, key string) error {
	if row.Disposition == "blocked-credential" && row.RequiredCredential == "" {
		return errors.New("blocked REST row has no required credential")
	}
	if (row.Disposition == "implemented" || row.Disposition == "protocol" || row.Disposition == "internal" || row.Disposition == "operator-only") != (len(row.CatalogOperations) > 0) {
		return fmt.Errorf("REST row %q catalog binding drifted", key)
	}
	return nil
}

func validRESTRow(row RESTRow, key string, seen map[string]bool, allowed []string) bool {
	return row.UpstreamID != "" && row.Method != "" && row.Path != "" && !seen[key] && slices.Contains(allowed, row.Disposition) && row.Reviewed
}

func validateGraphQLRows(graphql []GraphQLRow, allowed []string) error {
	seen := map[string]bool{}
	for _, row := range graphql {
		key := row.RootType + "." + row.Field
		if !validGraphQLRow(row, key, seen, allowed) {
			return fmt.Errorf("invalid GraphQL coverage row %q", key)
		}
		seen[key] = true
		if row.Disposition == "graphql" && (row.CatalogOperation == "" || len(row.PersistedDigest) != 64) {
			return fmt.Errorf("GraphQL row %q is not persisted", key)
		}
		if row.Deprecated != (row.Disposition == "blocked-upstream") {
			return fmt.Errorf("GraphQL deprecation disposition drifted for %q", key)
		}
	}
	return nil
}

func validGraphQLRow(row GraphQLRow, key string, seen map[string]bool, allowed []string) bool {
	return (row.RootType == "query" || row.RootType == "mutation") && row.Field != "" && !seen[key] && slices.Contains(allowed, row.Disposition) && row.Reviewed
}

func validateReviewArtifacts() error {
	if !json.Valid(reviewRaw) || !strings.Contains(string(reviewRaw), `"enterprise"`) {
		return errors.New("high-risk review artifact is invalid")
	}
	var overrides struct {
		Version  int                 `json:"version"`
		REST     map[string][]string `json:"rest_operation_names"`
		HighRisk []string            `json:"high_risk_operations"`
	}
	if json.Unmarshal(overridesRaw, &overrides) != nil || overrides.Version != 1 || len(overrides.REST) == 0 || len(overrides.HighRisk) == 0 {
		return errors.New("reviewed inventory overrides are invalid")
	}
	return nil
}
