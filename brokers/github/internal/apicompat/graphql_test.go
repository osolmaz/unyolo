package apicompat

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/githubauth"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/upstream"
)

func graphQLBody(t *testing.T, query string, variables map[string]any, operationName string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables, "operationName": operationName})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func classify(t *testing.T, query string, variables map[string]any) GraphQLRequest {
	t.Helper()
	request, err := ClassifyGraphQL(graphQLBody(t, query, variables, ""))
	if err != nil {
		t.Fatalf("ClassifyGraphQL(%s) error = %v", query, err)
	}
	return request
}

func TestClassifyGraphQLIntrospection(t *testing.T) {
	request := classify(t, `query PullRequest_fields {
		PullRequest: __type(name: "PullRequest") { fields(includeDeprecated: true) { name } }
		__typename
	}`, nil)
	if request.Kind != GraphQLSchema || len(request.Repositories) != 0 {
		t.Fatalf("request = %+v", request)
	}
}

func TestClassifyGraphQLRepositoryNetworkQuery(t *testing.T) {
	request := classify(t, `query RepositoryNetwork($owner: String!, $name: String = "widgets") {
		viewer { login }
		repo_000: repository(owner: $owner, name: $name) { id parent { nameWithOwner } }
		repo_001: repository(owner: "ACME", name: "Widgets", followRenames: true) { id }
		repo_002: repository(owner: "acme", name: "docs") { id ...repo }
	}
	fragment repo on Repository { name }`, map[string]any{"owner": "acme"})
	want := []githubauth.Repository{{Owner: "acme", Name: "widgets"}, {Owner: "acme", Name: "docs"}}
	if request.Kind != GraphQLRead || !reflect.DeepEqual(request.Repositories, want) {
		t.Fatalf("request = %+v, want repositories %+v", request, want)
	}
}

func TestClassifyGraphQLSelectsNamedOperation(t *testing.T) {
	body := graphQLBody(t, `query A { viewer { login } } query B { repository(owner: "acme", name: "widgets") { id } }`, nil, "B")
	request, err := ClassifyGraphQL(body)
	if err != nil || request.Kind != GraphQLRead {
		t.Fatalf("request = %+v, err = %v", request, err)
	}
}

func TestClassifyGraphQLRefusesUnreviewedShapes(t *testing.T) {
	cases := map[string]string{
		`{ viewer { login } }`: "must also name a repository",
		`{ search(query: "x", type: REPOSITORY, first: 1) { repositoryCount } }`: "search is not served",
		`{ node(id: "x") { id } }`:                                             "node is not served",
		`{ ...Root } fragment Root on Query { viewer { login } }`:              "root fragments",
		`{ ... on Query { viewer { login } } }`:                                "root fragments",
		`{ repository(owner: "a", name: "b") @include(if: true) { id } }`:      "root directives",
		`query Q @cached { repository(owner: "a", name: "b") { id } }`:         "operation directives",
		`subscription { repository(owner: "a", name: "b") { id } }`:            "subscriptions",
		`mutation { addStar(input: {starrableId: "x"}) { clientMutationId } }`: "addStar is not served",
		`mutation { a: addComment(input: {subjectId: "x", body: "1"}) { clientMutationId } b: addComment(input: {subjectId: "x", body: "2"}) { clientMutationId } }`: "exactly one GraphQL mutation",
	}
	for query, fragment := range cases {
		_, err := ClassifyGraphQL(graphQLBody(t, query, nil, ""))
		assertRefusal(t, err, http.StatusForbidden, fragment)
	}
}

func TestClassifyGraphQLRefusesMalformedRequests(t *testing.T) {
	cases := map[string]string{
		`{"query": ""}`: "body is invalid",
		`{"query": "{ viewer { login } }", "extensions": {}}`:                                                    "body is invalid",
		`{"query": "{ viewer { login "}`:                                                                         "does not parse",
		`{"query": "query A { __typename } query B { __typename }"}`:                                             "set operationName",
		`{"query": "query A { __typename }", "operationName": "B"}`:                                              "exactly one GraphQL operation",
		`{"query": "{ repository(owner: \"a\", owner: \"b\", name: \"c\") { id } }"}`:                            "owner is repeated",
		`{"query": "{ repository(owner: \"a\") { id } }"}`:                                                       "owner and name",
		`{"query": "{ repository(owner: \"a\", name: \"b/c\") { id } }"}`:                                        "owner and name",
		`{"query": "{ repository(owner: \"a\", name: \"b\", first: 1) { id } }"}`:                                "owner and name",
		`{"query": "{ repository(owner: \"a\", name: \"b\", followRenames: 1) { id } }"}`:                        "followRenames",
		`{"query": "mutation { addComment(input: {body: \"x\"}) { clientMutationId } }"}`:                        "needs input.subjectId",
		`{"query": "mutation { addComment(input: {subjectId: \"x\", subjectId: \"y\"}) { clientMutationId } }"}`: "subjectId is repeated",
		`{"query": "mutation { addComment(id: \"x\") { clientMutationId } }"}`:                                   "exactly one input object",
	}
	for body, fragment := range cases {
		_, err := ClassifyGraphQL([]byte(body))
		assertRefusal(t, err, http.StatusBadRequest, fragment)
	}
}

func TestClassifyGraphQLMutationBuildsRESTEquivalentRequest(t *testing.T) {
	request := classify(t, `mutation PullRequestCreate($input: CreatePullRequestInput!) {
		createPullRequest(input: $input) { pullRequest { id url } }
	}`, map[string]any{"input": map[string]any{
		"repositoryId": "R_1", "baseRefName": "main", "headRefName": "feature/x", "title": "Work", "body": "Text", "draft": true,
	}})
	if request.Kind != GraphQLMutation || request.Mutation.NodeID != "R_1" || request.Mutation.Operation != "pull_request.create" {
		t.Fatalf("request = %+v", request)
	}
	policyRequest, err := request.Mutation.Request(githubauth.Node{ID: "R_1", Type: "Repository", Owner: "acme", Repository: "widgets"})
	if err != nil {
		t.Fatal(err)
	}
	want := policy.Request{Operation: "pull_request.create", Target: policy.Target{Kind: "repo", Owner: "acme", Name: "widgets"},
		Attrs: map[string]string{"base_ref": "refs/heads/main", "head_ref": "refs/heads/feature/x", "ref": "refs/heads/feature/x"}}
	if !reflect.DeepEqual(policyRequest, want) {
		t.Fatalf("policy request = %+v, want %+v", policyRequest, want)
	}
}

func TestClassifyGraphQLMergeUsesRESTMergeMethod(t *testing.T) {
	request := classify(t, `mutation { mergePullRequest(input: {pullRequestId: "PR_1", mergeMethod: SQUASH, commitHeadline: "x"}) { clientMutationId } }`, nil)
	policyRequest, err := request.Mutation.Request(githubauth.Node{Type: "PullRequest", Owner: "acme", Repository: "widgets", Number: 9})
	if err != nil {
		t.Fatal(err)
	}
	want := policy.Request{Operation: "pull_request.merge", Target: policy.Target{Kind: "pull_request", Owner: "acme", Repo: "widgets", Number: 9},
		Attrs: map[string]string{"merge_method": "squash"}}
	if !reflect.DeepEqual(policyRequest, want) {
		t.Fatalf("policy request = %+v, want %+v", policyRequest, want)
	}
}

func TestMutationRequestChecksSubject(t *testing.T) {
	request := classify(t, `mutation { addComment(input: {subjectId: "I_1", body: "hi"}) { clientMutationId } }`, nil)
	if _, err := request.Mutation.Request(githubauth.Node{Type: "Repository", Owner: "acme", Repository: "widgets"}); err == nil {
		t.Fatal("repository subject accepted for addComment")
	}
	if _, err := request.Mutation.Request(githubauth.Node{Type: "Issue", Owner: "acme", Repository: "widgets"}); err == nil {
		t.Fatal("unnumbered issue subject accepted")
	}
	policyRequest, err := request.Mutation.Request(githubauth.Node{Type: "PullRequest", Owner: "acme", Repository: "widgets", Number: 3})
	if err != nil || policyRequest.Target.Kind != "issue" || policyRequest.Target.Number != 3 || policyRequest.Attrs != nil {
		t.Fatalf("policy request = %+v, err = %v", policyRequest, err)
	}
}

func TestMutationRefusesUnreviewedInputFields(t *testing.T) {
	for _, query := range []string{
		`mutation { createIssue(input: {repositoryId: "R_1", title: "x", labelIds: ["L_1"]}) { clientMutationId } }`,
		`mutation { createPullRequest(input: {repositoryId: "R_1", baseRefName: "main", headRefName: "x", headRepositoryId: "R_2", title: "x"}) { clientMutationId } }`,
		`mutation { addPullRequestReview(input: {pullRequestId: "PR_1", event: COMMENT, comments: [{path: "a", position: 1, body: "x"}]}) { clientMutationId } }`,
	} {
		_, err := ClassifyGraphQL(graphQLBody(t, query, nil, ""))
		assertRefusal(t, err, http.StatusForbidden, "is not served")
	}
}

func TestMutationTableMatchesPinnedSchemaAndCatalog(t *testing.T) {
	inputs := pinnedMutationInputs(t)
	for _, field := range MutationFields() {
		spec := mutationSpecs[field]
		accepted, found := inputs[field]
		if !found {
			t.Fatalf("mutation %s is absent from the pinned schema", field)
		}
		names := append([]string{"clientMutationId", spec.subject}, spec.fields...)
		for name := range spec.renames {
			names = append(names, name)
		}
		for _, name := range names {
			if !slices.Contains(accepted, name) {
				t.Fatalf("mutation %s input field %s is absent from the pinned schema", field, name)
			}
		}
		if _, err := servableDescriptor(spec.operation); err != nil {
			t.Fatalf("mutation %s maps to unservable %s: %v", field, spec.operation, err)
		}
	}
}

func pinnedMutationInputs(t *testing.T) map[string][]string {
	t.Helper()
	raw, err := upstream.Read("graphql-introspection-2026-07-14.json")
	if err != nil {
		t.Fatal(err)
	}
	type typeRef struct {
		Name   string   `json:"name"`
		OfType *typeRef `json:"ofType"`
	}
	var schema struct {
		Data struct {
			Schema struct {
				Types []struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
						Args []struct {
							Name string  `json:"name"`
							Type typeRef `json:"type"`
						} `json:"args"`
					} `json:"fields"`
					InputFields []struct {
						Name string `json:"name"`
					} `json:"inputFields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	inputTypes := map[string][]string{}
	mutationInputType := map[string]string{}
	for _, typ := range schema.Data.Schema.Types {
		for _, field := range typ.InputFields {
			inputTypes[typ.Name] = append(inputTypes[typ.Name], field.Name)
		}
		if typ.Name != "Mutation" {
			continue
		}
		for _, field := range typ.Fields {
			for _, arg := range field.Args {
				ref := &arg.Type
				for ref.OfType != nil {
					ref = ref.OfType
				}
				if arg.Name == "input" {
					mutationInputType[field.Name] = ref.Name
				}
			}
		}
	}
	result := map[string][]string{}
	for field, input := range mutationInputType {
		result[field] = inputTypes[input]
	}
	return result
}

func TestRefusalErrorText(t *testing.T) {
	err := error(unsupported("x %d", 1))
	var refusal *Refusal
	if !errors.As(err, &refusal) || err.Error() != "gh-broker: x 1" || !strings.HasPrefix(refusal.Message, "gh-broker:") {
		t.Fatalf("refusal = %v", err)
	}
}
