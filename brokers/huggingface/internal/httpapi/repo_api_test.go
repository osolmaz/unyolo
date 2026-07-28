package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/config"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/policy"
	"github.com/osolmaz/unyolo/telemetry/audit"
)

func TestAPIReposListsOnlyPolicyMetadata(t *testing.T) {
	var auditLog bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/datasets" || r.URL.Query().Get("author") != "acme" || r.URL.Query().Get("limit") != "100" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatalf("upstream list request = %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`[{"id":"acme/secret"},{"id":"acme/repo","private":true},{"id":"acme/split"},{"id":"acme/other"}]`))
	}))
	defer upstream.Close()
	policyJSON := `{"rules":[
		{"id":"deny-secret","effect":"deny","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"secret"}]},
		{"id":"deny-other","effect":"deny","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"other"}]},
		{"id":"list-repo","effect":"allow","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]},
		{"id":"list-split","effect":"allow","clients":["agent"],"operations":["repo.list"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"split"}]},
		{"id":"metadata-split","effect":"allow","clients":["agent"],"operations":["repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"split"}]},
		{"id":"list-wildcard","effect":"allow","clients":["agent"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"*"}]},
		{"id":"other-client","effect":"allow","clients":["other"],"operations":["repo.list","repo.metadata.read"],"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"other"}]}
	]}`
	scp, err := policy.Parse([]byte(policyJSON))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken: testToken,
			Clients: []config.Client{
				{Name: "agent", Secret: testSecret},
				{Name: "other", Secret: testOtherSecret},
			},
			StateDir:     filepath.Join(t.TempDir(), "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: upstream.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodGet, broker.URL+"/api/repos?type=dataset&owner=acme", "Bearer "+testSecret, nil)
	repos := decodeAPIRepoList(t, body)
	if resp.StatusCode != http.StatusOK || !repoNamesEqual(repos, []string{"repo", "split"}) {
		t.Fatalf("repo list = %d %s, want exact agent repos from combined and split rules", resp.StatusCode, body)
	}
	if strings.Contains(body, "refs/") || strings.Contains(body, "commit") || strings.Contains(body, "README") {
		t.Fatalf("repo list leaked content metadata: %s", body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/repos?type=dataset&owner=acme&limit=1", "Bearer "+testSecret, nil)
	if limited := decodeAPIRepoList(t, body); resp.StatusCode != http.StatusOK || !repoNamesEqual(limited, []string{"repo"}) {
		t.Fatalf("filtered limited repo list = %d %s", resp.StatusCode, body)
	}
	if got := auditLog.String(); !strings.Contains(got, `"operation":"repo.list"`) ||
		!strings.Contains(got, `"target":"repos"`) ||
		!strings.Contains(got, `"decision":"allowed"`) ||
		!strings.Contains(got, `"client":"agent"`) {
		t.Fatalf("repo list audit = %s, want allowed repo.list entry", got)
	}
	beforeInvalidAudit := auditLog.Len()
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/repos?cursor=bad", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "invalid_cursor" {
		t.Fatalf("invalid cursor = %d %s, want 400 invalid_cursor", resp.StatusCode, body)
	}
	if got := auditLog.String()[beforeInvalidAudit:]; !strings.Contains(got, `"operation":"repo.list"`) ||
		!strings.Contains(got, `"target":"repos"`) ||
		!strings.Contains(got, `"decision":"refused"`) ||
		!strings.Contains(got, `"reason":"invalid_cursor"`) {
		t.Fatalf("invalid cursor audit = %s, want refused repo.list entry", got)
	}
	beforeInvalidAudit = auditLog.Len()
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/repos?limit=0", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusBadRequest || decodeJSendFailReason(t, body) != "invalid_limit" {
		t.Fatalf("invalid limit = %d %s, want 400 invalid_limit", resp.StatusCode, body)
	}
	if got := auditLog.String()[beforeInvalidAudit:]; !strings.Contains(got, `"reason":"invalid_limit"`) {
		t.Fatalf("invalid limit audit = %s, want invalid_limit", got)
	}
}

func TestAPIUnknownRoutesAreAudited(t *testing.T) {
	var auditLog bytes.Buffer
	scp, err := policy.Parse([]byte(emptyPolicyJSON()))
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Options{
		Config: config.Config{
			HFToken:      testToken,
			Clients:      []config.Client{{Name: "agent", Secret: testSecret}},
			StateDir:     filepath.Join(t.TempDir(), "state"),
			MaxPackBytes: 25 * 1024 * 1024,
			HFTimeout:    10 * time.Second,
		},
		Scope:           scp,
		Audit:           audit.New(&auditLog),
		UpstreamBaseURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	broker := httptest.NewServer(handler)
	defer broker.Close()

	resp, body := doRequest(t, http.MethodPut, broker.URL+"/api/grants", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed || decodeJSendFailReason(t, body) != "method_not_allowed" {
		t.Fatalf("method mismatch = %d %s, want 405 method_not_allowed", resp.StatusCode, body)
	}
	resp, body = doRequest(t, http.MethodGet, broker.URL+"/api/unknown", "Bearer "+testSecret, nil)
	if resp.StatusCode != http.StatusNotFound || decodeJSendFailReason(t, body) != "not_found" {
		t.Fatalf("unknown API route = %d %s, want 404 not_found", resp.StatusCode, body)
	}
	got := auditLog.String()
	for _, want := range []string{
		`"operation":"api"`,
		`"target":"/api/grants"`,
		`"reason":"method_not_allowed"`,
		`"target":"/api/unknown"`,
		`"reason":"not_found"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("API route audit = %s, missing %s", got, want)
		}
	}
}

func repoNamesEqual(repos []apiRepoBody, names []string) bool {
	if len(repos) != len(names) {
		return false
	}
	for i, repo := range repos {
		if repo.Name != names[i] {
			return false
		}
	}
	return true
}
