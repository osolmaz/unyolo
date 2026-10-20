package apicompat

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/opbinding"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

func matchRequest(t *testing.T, method, path, rawQuery, body string) policy.Request {
	t.Helper()
	match, err := MatchREST(method, path)
	if err != nil {
		t.Fatalf("MatchREST(%s %s) error = %v", method, path, err)
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		t.Fatal(err)
	}
	request, err := match.Request(query, []byte(body))
	if err != nil {
		t.Fatalf("Request(%s %s) error = %v", method, path, err)
	}
	return request
}

func assertRefusal(t *testing.T, err error, status int, fragment string) {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Status != status || !strings.Contains(refusal.Message, fragment) {
		t.Fatalf("error = %v, want %d refusal containing %q", err, status, fragment)
	}
}

func TestMatchRESTClassifiesPullRequestRead(t *testing.T) {
	request := matchRequest(t, http.MethodGet, "/repos/acme/widgets/pulls/5", "", "")
	want := policy.Request{
		Operation: "pull_request.get",
		Target:    policy.Target{Kind: "pull_request", Owner: "acme", Repo: "widgets", Number: 5},
	}
	if !reflect.DeepEqual(request, want) {
		t.Fatalf("request = %+v, want %+v", request, want)
	}
}

func TestMatchRESTPrefersLiteralSegments(t *testing.T) {
	match, err := MatchREST(http.MethodGet, "/repos/acme/widgets/pulls/comments")
	if err != nil {
		t.Fatal(err)
	}
	if match.Binding.PathTemplate != "/repos/{owner}/{repo}/pulls/comments" {
		t.Fatalf("template = %s", match.Binding.PathTemplate)
	}
}

func TestMatchRESTLetsTerminalPathSpanSegments(t *testing.T) {
	request := matchRequest(t, http.MethodGet, "/repos/acme/widgets/contents/docs/read%20me.md", "ref=dev", "")
	if request.Operation != "repo.contents.read" || request.Target != (policy.Target{Kind: "repo", Owner: "acme", Name: "widgets"}) {
		t.Fatalf("request = %+v", request)
	}
	want := map[string]string{"path": "docs/read me.md", "selector_path": "docs/read me.md", "ref": "dev"}
	if !reflect.DeepEqual(request.Attrs, want) {
		t.Fatalf("attrs = %v, want %v", request.Attrs, want)
	}
	match, err := MatchREST(http.MethodGet, "/repos/acme/widgets/contents/docs/read%20me.md")
	if err != nil || match.Path != "/repos/acme/widgets/contents/docs/read%20me.md" {
		t.Fatalf("path = %q, err = %v", match.Path, err)
	}
}

func TestMatchRESTDerivesBodyAttributes(t *testing.T) {
	request := matchRequest(t, http.MethodPost, "/repos/acme/widgets/pulls", "", `{"title":"Work","head":"feature/x","base":"main"}`)
	want := map[string]string{"base_ref": "refs/heads/main", "head_ref": "refs/heads/feature/x", "ref": "refs/heads/feature/x"}
	if request.Operation != "pull_request.create" || !reflect.DeepEqual(request.Attrs, want) {
		t.Fatalf("request = %+v, want attrs %v", request, want)
	}
}

func TestMatchRESTUsesNumericTargetID(t *testing.T) {
	match, err := MatchREST(http.MethodGet, "/repos/acme/widgets/releases/42")
	if err != nil {
		t.Fatal(err)
	}
	request, err := match.Request(nil, nil)
	if err != nil || request.Target.ID != 42 || request.Target.Repo != "widgets" {
		t.Fatalf("request = %+v, err = %v", request, err)
	}
}

func TestMatchRESTRefusesUnsafePaths(t *testing.T) {
	for _, path := range []string{
		"/repos/acme/widgets/contents/a%2Fb",
		"/repos/acme/../widgets",
		"/repos/acme/widgets/pulls/%2E%2E",
		"/repos//widgets",
		"/repos/acme/widgets/pulls/",
		"/repos/acme/widgets/pulls/%zz",
	} {
		_, err := MatchREST(http.MethodGet, path)
		assertRefusal(t, err, http.StatusBadRequest, "unsupported segment")
	}
}

func TestMatchRESTRefusesUnknownRoutes(t *testing.T) {
	for _, path := range []string{"", "/", "repos/acme/widgets", "/repos/acme/widgets/nothing-here", "/rep%6Fs/acme/widgets"} {
		_, err := MatchREST(http.MethodGet, path)
		assertRefusal(t, err, http.StatusNotFound, "Not Found")
	}
	_, err := MatchREST("TRACE", "/repos/acme/widgets")
	assertRefusal(t, err, http.StatusNotFound, "Not Found")
}

func TestMatchRESTRefusesUnservableOperations(t *testing.T) {
	cases := map[string]string{
		"/repos/acme/widgets": "more than one operation",
		"/repos/acme/widgets/actions/runners/registration-token": "secret material",
		"/user/repos": "user credential",
		"/orgs/acme/actions/runners/registration-token": "secret material",
	}
	methods := map[string]string{
		"/repos/acme/widgets": http.MethodPatch, "/repos/acme/widgets/actions/runners/registration-token": http.MethodPost,
		"/user/repos": http.MethodGet, "/orgs/acme/actions/runners/registration-token": http.MethodPost,
	}
	for path, fragment := range cases {
		_, err := MatchREST(methods[path], path)
		assertRefusal(t, err, http.StatusForbidden, fragment)
	}
	match, err := MatchREST(http.MethodGet, "/orgs/acme/repos")
	if err != nil {
		t.Fatal(err)
	}
	_, err = match.Request(nil, nil)
	assertRefusal(t, err, http.StatusForbidden, "not scoped to one repository")
}

func TestMatchRESTRefusesAmbiguousOrInvalidInput(t *testing.T) {
	match, err := MatchREST(http.MethodPost, "/repos/acme/widgets/pulls")
	if err != nil {
		t.Fatal(err)
	}
	for body, fragment := range map[string]string{
		`{"head":"a"`:                   "not valid JSON",
		`{"head":"a","head":"b"}`:       "not valid JSON",
		`{"head":"a","base":["x","y"]}`: "base_ref has 2 values",
	} {
		_, err := match.Request(nil, []byte(body))
		var refusal *Refusal
		if !errors.As(err, &refusal) || !strings.Contains(refusal.Message, fragment) {
			t.Fatalf("Request(%s) error = %v, want %q", body, err, fragment)
		}
	}
	read, err := MatchREST(http.MethodGet, "/repos/acme/widgets/pulls/first")
	if err != nil {
		t.Fatal(err)
	}
	_, err = read.Request(nil, nil)
	assertRefusal(t, err, http.StatusBadRequest, "invalid number")
}

func TestMatchRESTKeepsRepeatedQueryValuesVisible(t *testing.T) {
	match, err := MatchREST(http.MethodGet, "/repos/acme/widgets/contents/README.md")
	if err != nil {
		t.Fatal(err)
	}
	_, err = match.Request(url.Values{"ref": {"main", "dev"}}, nil)
	assertRefusal(t, err, http.StatusForbidden, "ref has 2 values")
}

// Every servable repository binding must produce a policy request for a
// representative path, so no reviewed target field is left unhandled.
func TestEveryServableRepositoryBindingBuildsARequest(t *testing.T) {
	bindings, err := opbinding.All()
	if err != nil {
		t.Fatal(err)
	}
	served := 0
	for _, binding := range bindings {
		path := samplePath(binding.PathTemplate)
		match, err := MatchREST(binding.Method, path)
		if err != nil || match.Binding.ID != binding.ID {
			continue
		}
		request, err := match.Request(nil, nil)
		var refusal *Refusal
		if errors.As(err, &refusal) && strings.Contains(refusal.Message, "not scoped to one repository") {
			continue
		}
		if err != nil || !policy.IsOperation(string(request.Operation)) {
			t.Fatalf("%s %s: request = %+v, err = %v", binding.Method, path, request, err)
		}
		served++
	}
	if served < 400 {
		t.Fatalf("served bindings = %d, want the repository surface", served)
	}
}

func samplePath(template string) string {
	parts := strings.Split(template, "/")
	for index, part := range parts {
		if name, ok := templateParameter(part); ok {
			parts[index] = sampleValue(name)
		}
	}
	return strings.Join(parts, "/")
}

func sampleValue(name string) string {
	switch {
	case strings.HasSuffix(name, "_id") || strings.HasSuffix(name, "_number") || name == "pull_number" || name == "issue_number":
		return "7"
	default:
		return "sample-" + strings.ReplaceAll(name, "_", "-")
	}
}
