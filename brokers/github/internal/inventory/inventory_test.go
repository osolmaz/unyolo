package inventory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/upstream"
)

func TestCoverageIsExhaustiveAgainstPinnedSources(t *testing.T) {
	rest, err := AllREST()
	if err != nil {
		t.Fatal(err)
	}
	graphql, err := AllGraphQL()
	if err != nil {
		t.Fatal(err)
	}
	data, err := upstream.Read("rest-api-2026-03-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var openapi struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &openapi); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, item := range openapi.Paths {
		for method := range item {
			if map[string]bool{"get": true, "put": true, "post": true, "delete": true, "patch": true, "head": true}[method] {
				count++
			}
		}
	}
	if count != len(rest) {
		t.Fatalf("pinned REST=%d coverage=%d", count, len(rest))
	}
	data, err = upstream.Read("graphql-introspection-2026-07-14.json")
	if err != nil {
		t.Fatal(err)
	}
	var response struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string            `json:"name"`
					Fields []json.RawMessage `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(data, &response); err != nil {
		t.Fatal(err)
	}
	roots := 0
	for _, typ := range response.Data.Schema.Types {
		if typ.Name == "Query" || typ.Name == "Mutation" {
			roots += len(typ.Fields)
		}
	}
	if roots != len(graphql) {
		t.Fatalf("pinned GraphQL=%d coverage=%d", roots, len(graphql))
	}
}

func TestRESTPermissionsMatchPinnedOfficialMatrix(t *testing.T) {
	data, err := upstream.Read("github-app-permissions-2026-03-10.json")
	if err != nil {
		t.Fatal(err)
	}
	var groups map[string]struct {
		Permissions []struct {
			Verb, RequestPath, Access string
			User                      bool `json:"user-to-server"`
			Server                    bool `json:"server-to-server"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &groups); err != nil {
		t.Fatal(err)
	}
	expected := map[string]map[string]string{}
	for permission, group := range groups {
		for _, route := range group.Permissions {
			if !route.User && !route.Server {
				continue
			}
			key := strings.ToUpper(route.Verb) + " " + route.RequestPath
			if expected[key] == nil {
				expected[key] = map[string]string{}
			}
			access := route.Access
			if access == "" {
				access = "read"
			}
			if expected[key][permission] != "write" || access == "write" {
				expected[key][permission] = access
			}
		}
	}
	rows, err := AllREST()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		key := row.Method + " " + row.Path
		if !reflect.DeepEqual(row.RequiredPermissions, expected[key]) {
			t.Fatalf("permissions for %s=%v want %v", key, row.RequiredPermissions, expected[key])
		}
	}
}

func TestEveryHighRiskClassHasReviewedRows(t *testing.T) {
	var review struct {
		Classes []struct {
			Name       string   `json:"name"`
			Operations []string `json:"operations"`
		} `json:"classes"`
	}
	if err := json.Unmarshal(reviewRaw, &review); err != nil {
		t.Fatal(err)
	}
	if len(review.Classes) != 6 {
		t.Fatalf("classes=%d", len(review.Classes))
	}
	for _, class := range review.Classes {
		if len(class.Operations) == 0 {
			t.Fatalf("risk class %q is empty", class.Name)
		}
	}
}

func TestCoverageValidationFailsClosed(t *testing.T) {
	rest, err := AllREST()
	if err != nil {
		t.Fatal(err)
	}
	graphql, err := AllGraphQL()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]RESTRow, []GraphQLRow)
	}{
		{"rest count", func(rest []RESTRow, _ []GraphQLRow) { rest[0] = RESTRow{} }},
		{"rest duplicate", func(rest []RESTRow, _ []GraphQLRow) { rest[1].Method, rest[1].Path = rest[0].Method, rest[0].Path }},
		{"rest disposition", func(rest []RESTRow, _ []GraphQLRow) { rest[0].Disposition = "raw" }},
		{"rest review", func(rest []RESTRow, _ []GraphQLRow) { rest[0].Reviewed = false }},
		{"blocked credential", func(rest []RESTRow, _ []GraphQLRow) {
			rest[0].Disposition, rest[0].RequiredCredential, rest[0].CatalogOperations = "blocked-credential", "", nil
		}},
		{"rest catalog", func(rest []RESTRow, _ []GraphQLRow) {
			rest[0].Disposition, rest[0].CatalogOperations = "local", []string{"bad"}
		}},
		{"graphql root", func(_ []RESTRow, graphql []GraphQLRow) { graphql[0].RootType = "subscription" }},
		{"graphql duplicate", func(_ []RESTRow, graphql []GraphQLRow) {
			graphql[1].RootType, graphql[1].Field = graphql[0].RootType, graphql[0].Field
		}},
		{"graphql review", func(_ []RESTRow, graphql []GraphQLRow) { graphql[0].Reviewed = false }},
		{"graphql digest", func(_ []RESTRow, graphql []GraphQLRow) {
			graphql[0].Deprecated, graphql[0].Disposition, graphql[0].CatalogOperation, graphql[0].PersistedDigest = false, "graphql", "operation", "short"
		}},
		{"graphql deprecation", func(_ []RESTRow, graphql []GraphQLRow) { graphql[0].Deprecated = !graphql[0].Deprecated }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restCopy := append([]RESTRow(nil), rest...)
			graphqlCopy := append([]GraphQLRow(nil), graphql...)
			test.mutate(restCopy, graphqlCopy)
			if err := Validate(restCopy, graphqlCopy); err == nil {
				t.Fatal("invalid coverage accepted")
			}
		})
	}
	if err := Validate(rest[:len(rest)-1], graphql); err == nil {
		t.Fatal("short REST inventory accepted")
	}

	originalReview := reviewRaw
	reviewRaw = []byte(`{}`)
	if err := Validate(rest, graphql); err == nil {
		t.Fatal("invalid risk review accepted")
	}
	reviewRaw = originalReview
	originalOverrides := overridesRaw
	overridesRaw = []byte(`{}`)
	if err := Validate(rest, graphql); err == nil {
		t.Fatal("invalid overrides accepted")
	}
	overridesRaw = originalOverrides
}
