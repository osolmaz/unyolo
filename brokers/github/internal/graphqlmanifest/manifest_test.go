package graphqlmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

func TestManifestIsPinnedAndRejectsArbitraryGraphQL(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 284 {
		t.Fatalf("documents=%d", len(values))
	}
	for _, value := range values {
		if strings.Contains(value.Document, "__schema") || strings.Contains(value.Document, "@include") || strings.Contains(value.Document, "$document") {
			t.Fatalf("unsafe document %q", value.CatalogOperation)
		}
	}
}

func TestKnownRootUsesPersistedDigest(t *testing.T) {
	value, found := ByOperation("repo.read_repository")
	if !found || value.RootField != "repository" || len(value.SHA256) != 64 {
		t.Fatalf("document=%+v found=%v", value, found)
	}
}

func TestMutationSelectionsMatchGeneratedResults(t *testing.T) {
	value, found := ByOperation("comment.add_comment")
	if !found || !strings.Contains(value.Document, "{ __typename clientMutationId }") {
		t.Fatalf("mutation selection does not include validated fields: %+v", value)
	}
}

func TestPinnedRootFieldParsing(t *testing.T) {
	if _, err := pinnedRootFields([]byte(`not-json`)); err == nil {
		t.Fatal("invalid introspection accepted")
	}
	fields, err := pinnedRootFields([]byte(`{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"viewer"}]},{"name":"Mutation","fields":[{"name":"addComment"}]},{"name":"Issue","fields":[{"name":"title"}]}]}}}`))
	if err != nil || !fields["query.viewer"] || !fields["mutation.addComment"] || fields["Issue.title"] {
		t.Fatalf("fields=%v err=%v", fields, err)
	}
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestManifestLoadFailsClosed(t *testing.T) {
	originalRaw := append([]byte(nil), raw...)
	t.Cleanup(func() {
		raw = originalRaw
		once = sync.Once{}
		loaded, loadErr, documentsByOperation = Manifest{}, nil, nil
		_, _ = All()
	})
	var valid Manifest
	if err := json.Unmarshal(originalRaw, &valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{"version", func(value *Manifest) { value.Version = 2 }},
		{"fingerprint", func(value *Manifest) { value.SchemaFingerprint = "sha256:bad" }},
		{"sort", func(value *Manifest) { value.Documents[1].CatalogOperation = value.Documents[0].CatalogOperation }},
		{"root", func(value *Manifest) { value.Documents[0].RootField = "notARealRoot" }},
		{"catalog", func(value *Manifest) {
			last := &value.Documents[len(value.Documents)-1]
			last.CatalogOperation = "zzz.not_real"
		}},
		{"document", func(value *Manifest) { value.Documents[0].Document += " @skip" }},
		{"variables", func(value *Manifest) {
			value.Documents[0].VariableSchema["additionalProperties"] = true
			digest := sha256.Sum256([]byte(value.Documents[0].Document))
			value.Documents[0].SHA256 = hex.EncodeToString(digest[:])
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, _ := json.Marshal(valid)
			var altered Manifest
			_ = json.Unmarshal(data, &altered)
			test.mutate(&altered)
			raw, _ = json.Marshal(altered)
			once = sync.Once{}
			loaded, loadErr, documentsByOperation = Manifest{}, nil, nil
			if _, err := All(); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}
