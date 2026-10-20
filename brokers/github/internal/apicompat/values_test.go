package apicompat

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

func firstArgument(t *testing.T, query string) *ast.Value {
	t.Helper()
	document, err := parser.ParseQuery(&ast.Source{Input: query})
	if err != nil {
		t.Fatal(err)
	}
	field, isField := document.Operations[0].SelectionSet[0].(*ast.Field)
	if !isField {
		t.Fatal("first selection is not a field")
	}
	return field.Arguments[0].Value
}

func TestResolveValueCoversLiteralKinds(t *testing.T) {
	value, err := resolveValue(firstArgument(t, `{ f(a: [1, 2.5, true, null, ENUM, "s", """block""", {k: $v}]) }`), map[string]any{"v": "x"})
	if err != nil {
		t.Fatal(err)
	}
	want := []any{json.Number("1"), json.Number("2.5"), true, nil, "ENUM", "s", "block", map[string]any{"k": "x"}}
	if !reflect.DeepEqual(value, want) {
		t.Fatalf("value = %#v, want %#v", value, want)
	}
	if _, err := resolveValue(firstArgument(t, `{ f(a: [{k: 1, k: 2}]) }`), nil); err == nil {
		t.Fatal("repeated object field in a list accepted")
	}
	if _, err := resolveValue(firstArgument(t, `{ f(a: {o: {k: 1, k: 2}}) }`), nil); err == nil {
		t.Fatal("repeated nested object field accepted")
	}
}

func TestEffectiveVariablesRefusesRepeatedDefaultFields(t *testing.T) {
	_, err := ClassifyGraphQL(graphQLBody(t, `query($o: Input = {k: 1, k: 2}) { repository(owner: "a", name: "b") { id } }`, nil, ""))
	assertRefusal(t, err, http.StatusBadRequest, "k is repeated")
}

func TestServableDescriptorRefusesUnavailableOperations(t *testing.T) {
	_, err := servableDescriptor("missing.operation")
	assertRefusal(t, err, http.StatusForbidden, "not cataloged")
	_, err = servableDescriptor("repo.read_repository")
	assertRefusal(t, err, http.StatusForbidden, "not available to agents")
	_, err = Mutation{Field: "x", Operation: "missing.operation", nodeTypes: []string{"Issue"}}.Request(githubauth.Node{Type: "Issue", Number: 1})
	assertRefusal(t, err, http.StatusForbidden, "not cataloged")
}

func TestSetTargetFieldRefusesUnknownFields(t *testing.T) {
	err := setTargetField(&policy.Target{}, "installation_id", "1")
	assertRefusal(t, err, http.StatusForbidden, "installation_id")
}
