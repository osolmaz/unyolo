package openapidrift

import "testing"

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
	for _, value := range [][]byte{nil, []byte(`{}`), []byte(`{"paths":{"/repos":{"get":false}}}`)} {
		if _, err := Analyze(value, []byte(`{"paths":{"/ok":{"get":{}}}}`)); err == nil {
			t.Fatalf("invalid document accepted: %s", value)
		}
	}
}
