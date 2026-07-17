package openapidrift

import (
	"strings"
	"testing"
)

func TestAnalyzeClassifiesStructuralChanges(t *testing.T) {
	pinned := []byte(`{"security":[{"token":[]}],"paths":{"/repos":{"get":{"operationId":"repos/list","responses":{"200":{"description":"old"}}}},"/old":{"delete":{"operationId":"old/delete","deprecated":false,"responses":{"204":{}}}}}}`)
	current := []byte(`{"security":[{"other":[]}],"paths":{"/repos":{"get":{"operationId":"repos/view","deprecated":true,"responses":{"200":{"content":{"application/json":{"schema":{"type":"object","oneOf":[{"description":"ignored","type":"string"}]}}}}}}},"/new":{"post":{"operationId":"new/create","responses":{"201":{}}}}}}`)

	changes, err := Analyze(pinned, current)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		CategoryAuthentication: true,
		CategoryDeprecation:    true,
		CategoryOperation:      true,
		CategorySchema:         true,
	}
	for _, change := range changes {
		delete(want, change.Category)
	}
	if len(want) != 0 {
		t.Fatalf("missing change categories: %v; changes = %#v", want, changes)
	}
}

func TestAnalyzeIgnoresDocumentationChanges(t *testing.T) {
	pinned := []byte(`{"paths":{"/repos":{"get":{"operationId":"repos/list","summary":"old","responses":{"200":{"description":"old"}}}}}}`)
	current := []byte(`{"paths":{"/repos":{"get":{"operationId":"repos/list","summary":"new","responses":{"200":{"description":"new"}}}}}}`)

	changes, err := Analyze(pinned, current)
	if err != nil || len(changes) != 0 {
		t.Fatalf("Analyze() = %#v, %v", changes, err)
	}
}

func TestAnalyzeRejectsInvalidDocuments(t *testing.T) {
	for _, value := range [][]byte{nil, []byte(`{}`), []byte(`{"paths":{"/repos":false}}`), []byte(`{"paths":{"/repos":{"get":false}}}`)} {
		if _, err := Analyze(value, []byte(`{"paths":{"/ok":{"get":{}}}}`)); err == nil {
			t.Fatalf("invalid document accepted: %s", value)
		}
	}
}

func TestResolvePointerSupportsArraysAndRejectsInvalidTokens(t *testing.T) {
	root := map[string]any{"values": []any{map[string]any{"name": "first"}}}
	value, err := resolvePointer(root, "#/values/0/name")
	if err != nil || value != "first" {
		t.Fatalf("resolvePointer() = %#v, %v", value, err)
	}
	for _, reference := range []string{"#/values/nope", "#/values/-1", "#/values/1", "#/values/0/name/more"} {
		if _, err := resolvePointer(root, reference); err == nil {
			t.Fatalf("invalid pointer accepted: %s", reference)
		}
	}
}

func TestAnalyzeIncludesReferencedComponentsPathParametersAndSecuritySchemes(t *testing.T) {
	base := `{"security":[{"bearer":[]}],"components":{"schemas":{"RepoId":{"type":"string"}},"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}},"paths":{"/repos/{id}":{"parameters":[{"name":"id","in":"path","required":true,"schema":{"$ref":"#/components/schemas/RepoId"}}],"get":{"operationId":"repos/get","responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/RepoId"}}}}}}}}}`
	for name, current := range map[string]string{
		"component":       strings.Replace(base, `"RepoId":{"type":"string"}`, `"RepoId":{"type":"integer"}`, 1),
		"path parameter":  strings.Replace(base, `"required":true`, `"required":false`, 1),
		"security scheme": strings.Replace(base, `"type":"http","scheme":"bearer"`, `"type":"apiKey","in":"header","name":"authorization"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			changes, err := Analyze([]byte(base), []byte(current))
			if err != nil || len(changes) == 0 {
				t.Fatalf("Analyze() = %#v, %v", changes, err)
			}
			wantCategory := CategorySchema
			if name == "security scheme" {
				wantCategory = CategoryAuthentication
			}
			if changes[0].Category != wantCategory {
				t.Fatalf("change category = %q, want %q", changes[0].Category, wantCategory)
			}
		})
	}
}

func TestAnalyzeHandlesCyclesAndRejectsMissingReferences(t *testing.T) {
	cyclic := []byte(`{"components":{"schemas":{"Node":{"type":"object","properties":{"next":{"$ref":"#/components/schemas/Node"}}}}},"paths":{"/node":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Node"}}}}}}}}}`)
	changes, err := Analyze(cyclic, cyclic)
	if err != nil || len(changes) != 0 {
		t.Fatalf("cyclic Analyze() = %#v, %v", changes, err)
	}
	missing := []byte(`{"paths":{"/node":{"get":{"responses":{"200":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/Missing"}}}}}}}}}`)
	if _, err := Analyze(missing, missing); err == nil {
		t.Fatal("unresolved local reference accepted")
	}
}
