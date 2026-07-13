package opcatalog

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestCatalogValidatesAndContainsCanonicalOperations(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != ExpectedCount {
		t.Fatalf("catalog count=%d", len(values))
	}
	for _, name := range []string{"repo.metadata.read", "repo.contents.read", "repo.visibility.update", "pull_request.create", "pull_request.merge", "installation.repo.list"} {
		value, found := ByName(name)
		if !found {
			t.Fatalf("operation %q missing", name)
		}
		if name == "repo.visibility.update" || name == "pull_request.merge" {
			if !value.ExplicitOnly || value.Risk != RiskHigh || value.MaxUses != 1 {
				t.Fatalf("high-risk descriptor=%+v", value)
			}
		}
	}
	for _, removed := range []string{"pr.create", "pr.update", "pr.merge", "contents.read", "checks.read", "http.request", "graphql.execute"} {
		if _, found := ByName(removed); found {
			t.Fatalf("legacy or raw operation %q survived", removed)
		}
	}
}

func TestGeneratedCapabilityJSONMatchesCatalog(t *testing.T) {
	data, err := os.ReadFile("../../docs/generated/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(raw)) {
		t.Fatal("generated capability JSON is stale")
	}
}

func TestGitHubCatalogValidationFailsClosed(t *testing.T) {
	valid := MustAll()
	tests := []struct {
		name   string
		mutate func([]Descriptor)
	}{
		{"summary", func(values []Descriptor) { values[0].Summary = "" }},
		{"credential", func(values []Descriptor) { values[0].CredentialKind = "raw-token" }},
		{"binding", func(values []Descriptor) { values[0].UpstreamBindingIDs = nil }},
		{"sealed paths", func(values []Descriptor) {
			for index := range values {
				if values[index].Sealed {
					values[index].SealedInputPaths = nil
					return
				}
			}
		}},
		{"high risk", func(values []Descriptor) {
			for index := range values {
				if values[index].Risk == RiskHigh && values[index].AuthorizationMode == ModeExecution {
					values[index].ExplicitOnly = false
					values[index].Disposition = strings.ReplaceAll(values[index].Disposition, "X", "")
					return
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := slices.Clone(valid)
			test.mutate(values)
			if err := Validate(values); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}
