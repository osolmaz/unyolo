package upstreamdrift

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeClassifiesCapabilityDrift(t *testing.T) {
	pinned := fixtureSet(
		`{"paths":{"/repos/{owner}/{repo}":{"get":{"operationId":"repos/get","security":[{"app":[]}],"responses":{"200":{"description":"ok"}}}},"/old":{"delete":{"operationId":"old/delete","deprecated":false,"responses":{"204":{}}}}}}`,
		graphqlFixture("viewer", false, "String"),
		permissionFixture("GET", "/repos/{owner}/{repo}", "contents", "read"),
		[]string{"2022-11-28"},
	)
	current := fixtureSet(
		`{"paths":{"/repos/{owner}/{repo}":{"get":{"operationId":"repos/view","security":[{"user":[]}],"responses":{"200":{"content":{"application/json":{"schema":{"type":"object"}}}}}}},"/new":{"post":{"operationId":"new/create","responses":{"201":{}}}}}}`,
		graphqlFixture("viewer", true, "Int"),
		permissionFixture("GET", "/repos/{owner}/{repo}", "contents", "write"),
		[]string{"2026-03-10"},
	)

	report, err := Analyze(pinned, current)
	if err != nil {
		t.Fatal(err)
	}
	for _, category := range []string{CategoryAPIVersion, CategoryAuthentication, CategoryDeprecation, CategoryOperation, CategoryPermission, CategorySchema} {
		if !hasCategory(report.Changes, category) {
			t.Errorf("missing %s classification: %+v", category, report.Changes)
		}
	}
	if !report.HasDrift() || !report.RetrievedAt.Equal(current.Sources[0].RetrievedAt) {
		t.Fatalf("report = %+v", report)
	}
}

func TestAnalyzeIgnoresDocumentationOnlyChanges(t *testing.T) {
	pinned := fixtureSet(
		`{"paths":{"/repos":{"get":{"operationId":"repos/list","summary":"old","responses":{"200":{"description":"old"}}}}}}`,
		graphqlFixture("viewer", false, "String"),
		permissionFixture("GET", "/repos", "contents", "read"),
		[]string{"2026-03-10"},
	)
	current := fixtureSet(
		`{"paths":{"/repos":{"get":{"operationId":"repos/list","summary":"new","responses":{"200":{"description":"new"}}}}}}`,
		strings.ReplaceAll(graphqlFixture("viewer", false, "String"), `"description":null`, `"description":"new docs"`),
		permissionFixture("GET", "/repos", "contents", "read"),
		[]string{"2026-03-10"},
	)
	report, err := Analyze(pinned, current)
	if err != nil || report.HasDrift() {
		t.Fatalf("Analyze() = %+v, %v", report, err)
	}
}

func TestWriteMarkdownBoundsDetailsAndEscapesValues(t *testing.T) {
	changes := make([]Change, maxReportedChanges+5)
	for index := range changes {
		changes[index] = Change{Category: CategoryOperation, Kind: "added", Key: "key|`value"}
	}
	var output bytes.Buffer
	if err := WriteMarkdown(&output, Report{RetrievedAt: time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC), Changes: changes}); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Count(text, "- `operation`") != maxReportedChanges || !strings.Contains(text, "5 additional changes omitted") || strings.Contains(text, "key|`value") {
		t.Fatalf("unexpected report:\n%s", text)
	}
	if err := WriteMarkdown(nil, Report{}); err == nil {
		t.Fatal("nil writer accepted")
	}
	output.Reset()
	clean := Report{RetrievedAt: time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC), Sources: []Source{{Kind: "rest|api", Commit: "", SHA256: "abc"}}}
	if err := WriteMarkdown(&output, clean); err != nil || !strings.Contains(output.String(), "No snapshot refresh is required") || !strings.Contains(output.String(), "rest\\|api") {
		t.Fatalf("clean report = %q, %v", output.String(), err)
	}
}

func TestParsingRejectsInvalidInputs(t *testing.T) {
	for name, test := range map[string]func() error{
		"permissions": func() error { _, err := parsePermissions([]byte(`{}`)); return err },
		"graphql":     func() error { _, err := parseGraphQL([]byte(`{}`)); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if err := test(); err == nil {
				t.Fatal("invalid input accepted")
			}
		})
	}
}

func fixtureSet(rest, graphql, permissions string, versions []string) SnapshotSet {
	retrieved := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return SnapshotSet{REST: []byte(rest), GraphQL: []byte(graphql), Permissions: []byte(permissions), APIVersions: versions, Sources: []Source{{Kind: "rest", RetrievedAt: retrieved}}}
}

func graphqlFixture(field string, deprecated bool, scalar string) string {
	return `{"data":{"__schema":{"types":[{"kind":"OBJECT","name":"Query","description":null,"fields":[{"name":"` + field + `","description":null,"args":[],"type":{"kind":"SCALAR","name":"` + scalar + `"},"isDeprecated":` + boolText(deprecated) + `,"deprecationReason":"retired"}]},{"kind":"SCALAR","name":"String","description":null,"fields":null}]}}}`
}

func permissionFixture(method, path, permission, access string) string {
	return `{"` + permission + `":{"permissions":[{"verb":"` + method + `","requestPath":"` + path + `","access":"` + access + `","server-to-server":true}]}}`
}

func boolText(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func hasCategory(changes []Change, category string) bool {
	for _, change := range changes {
		if change.Category == category {
			return true
		}
	}
	return false
}
