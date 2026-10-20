package githubauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type compatGitHub struct {
	t        *testing.T
	mu       sync.Mutex
	minted   map[string][]map[string]any
	lookups  []string
	nodeBody func(installation string, id string) string
}

func (g *compatGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	installations := map[string]string{"/repos/acme/one/installation": "42", "/repos/acme/two/installation": "42", "/repos/other/three/installation": "43"}
	switch {
	case installations[r.URL.Path] != "":
		_, _ = io.WriteString(w, `{"id":`+installations[r.URL.Path]+`,"permissions":{"contents":"write","pull_requests":"write","issues":"read","administration":"write","workflows":"write"}}`)
	case r.URL.Path == "/app/installations":
		_, _ = io.WriteString(w, `[{"id":43,"permissions":{"issues":"read"}},{"id":42,"permissions":{"pull_requests":"write","contents":"read"}}]`)
	case strings.HasPrefix(r.URL.Path, "/app/installations/") && strings.HasSuffix(r.URL.Path, "/access_tokens"):
		g.mint(w, r, strings.Split(r.URL.Path, "/")[3])
	case r.URL.Path == "/repos/acme/one" || r.URL.Path == "/repos/acme/two" || r.URL.Path == "/repos/other/three":
		parts := strings.Split(r.URL.Path, "/")
		ids := map[string]string{"one": "1", "two": "2", "three": "3"}
		_, _ = io.WriteString(w, `{"id":`+ids[parts[3]]+`,"name":"`+parts[3]+`","owner":{"login":"`+parts[2]+`"}}`)
	case r.URL.Path == "/installation/token":
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/graphql":
		g.lookup(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (g *compatGitHub) mint(w http.ResponseWriter, r *http.Request, installation string) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		g.t.Fatal(err)
	}
	g.mu.Lock()
	g.minted[installation] = append(g.minted[installation], body)
	g.mu.Unlock()
	_, _ = io.WriteString(w, `{"token":"token-`+installation+`","expires_at":"2026-10-20T02:00:00Z"}`)
}

func (g *compatGitHub) lookup(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Variables map[string]string `json:"variables"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		g.t.Fatal(err)
	}
	installation := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer token-")
	g.mu.Lock()
	g.lookups = append(g.lookups, installation)
	g.mu.Unlock()
	_, _ = io.WriteString(w, g.nodeBody(installation, payload.Variables["id"]))
}

func newCompatGitHub(t *testing.T, nodeBody func(installation, id string) string) (*compatGitHub, *Manager) {
	t.Helper()
	fake := &compatGitHub{t: t, minted: map[string][]map[string]any{}, nodeBody: nodeBody}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	now := time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC)
	return fake, newAppTestManager(t, server, func() time.Time { return now })
}

func TestGraphQLReadCredentialNarrowsToRepositoriesAndReadPermissions(t *testing.T) {
	fake, manager := newCompatGitHub(t, nil)
	credential, err := manager.GraphQLReadCredential(t.Context(), []Repository{{Owner: "acme", Name: "one"}, {Owner: "acme", Name: "two"}})
	if err != nil {
		t.Fatal(err)
	}
	assertBearer(t, credential, "token-42")
	minted := fake.minted["42"]
	assertExactTokenRequest(t, minted[len(minted)-1], []int64{1, 2},
		map[string]string{"contents": "read", "issues": "read", "metadata": "read", "pull_requests": "read"})
	if _, err := manager.GraphQLReadCredential(t.Context(), []Repository{{Owner: "acme", Name: "one"}, {Owner: "other", Name: "three"}}); err == nil ||
		!strings.Contains(err.Error(), "one App installation") {
		t.Fatalf("cross-installation read error = %v", err)
	}
	if _, err := manager.GraphQLReadCredential(t.Context(), nil); err == nil {
		t.Fatal("empty repository list accepted")
	}
	if _, err := manager.GraphQLReadCredential(t.Context(), []Repository{{Owner: "acme", Name: "missing"}}); err == nil {
		t.Fatal("uninstalled repository accepted")
	}
}

func TestSchemaCredentialUsesLowestInstallationMetadataOnly(t *testing.T) {
	fake, manager := newCompatGitHub(t, nil)
	credential, err := manager.SchemaCredential(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	assertBearer(t, credential, "token-42")
	assertExactTokenRequest(t, fake.minted["42"][0], []int64{}, map[string]string{"metadata": "read"})
}

func TestResolveNodeTriesInstallationsInOrder(t *testing.T) {
	fake, manager := newCompatGitHub(t, func(installation, id string) string {
		switch {
		case id == "PR_1" && installation == "43":
			return `{"data":{"node":{"__typename":"PullRequest","number":5,"repository":{"name":"three","owner":{"login":"other"}}}}}`
		case id == "R_1" && installation == "42":
			return `{"data":{"node":{"__typename":"Repository","name":"one","owner":{"login":"acme"}}}}`
		case id == "X_1":
			return `{"data":{"node":{"__typename":"Label"}}}`
		default:
			return `{"data":{"node":null},"errors":[{"type":"NOT_FOUND","message":"Could not resolve"}]}`
		}
	})
	node, err := manager.ResolveNode(t.Context(), "PR_1")
	want := Node{ID: "PR_1", Type: "PullRequest", Owner: "other", Repository: "three", Number: 5}
	if err != nil || node != want {
		t.Fatalf("node = %+v, err = %v, want %+v", node, err, want)
	}
	if strings.Join(fake.lookups, ",") != "42,43" {
		t.Fatalf("lookups = %v, want lowest installation first", fake.lookups)
	}
	assertExactTokenRequest(t, fake.minted["42"][0], []int64{}, map[string]string{"metadata": "read", "pull_requests": "read"})
	assertExactTokenRequest(t, fake.minted["43"][0], []int64{}, map[string]string{"metadata": "read", "issues": "read"})
	repository, err := manager.ResolveNode(t.Context(), "R_1")
	if err != nil || repository != (Node{ID: "R_1", Type: "Repository", Owner: "acme", Repository: "one"}) {
		t.Fatalf("repository node = %+v, err = %v", repository, err)
	}
	for _, id := range []string{"missing", "X_1"} {
		if _, err := manager.ResolveNode(t.Context(), id); !errors.Is(err, ErrNodeNotFound) {
			t.Fatalf("ResolveNode(%s) error = %v, want ErrNodeNotFound", id, err)
		}
	}
	if _, err := manager.ResolveNode(t.Context(), " "); err == nil {
		t.Fatal("blank node id accepted")
	}
}

func TestDevelopmentCredentialServesCompatibilityLookups(t *testing.T) {
	var status = http.StatusOK
	var body = `{"data":{"node":{"__typename":"Issue","number":2,"repository":{"name":"one","owner":{"login":"acme"}}}}}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graphql" || r.Header.Get("Authorization") != "Bearer development-canary" {
			t.Fatalf("request = %s %q", r.URL.Path, r.Header.Get("Authorization"))
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL)
	manager, err := New(Config{DevelopmentToken: []byte("development-canary"), DevelopmentTokenFile: "/protected/token", APIBaseURL: base, WebBaseURL: base, HTTPClient: server.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for _, get := range []func() (*Credential, error){
		func() (*Credential, error) { return manager.SchemaCredential(t.Context()) },
		func() (*Credential, error) {
			return manager.GraphQLReadCredential(t.Context(), []Repository{{Owner: "acme", Name: "one"}})
		},
	} {
		credential, err := get()
		if err != nil {
			t.Fatal(err)
		}
		assertBearer(t, credential, "development-canary")
	}
	node, err := manager.ResolveNode(t.Context(), "I_1")
	if err != nil || node.Number != 2 || node.Type != "Issue" {
		t.Fatalf("node = %+v, err = %v", node, err)
	}
	for nextStatus, nextBody := range map[int]string{http.StatusBadGateway: `{"message":"bad"}`, http.StatusOK: `{"data":`} {
		status, body = nextStatus, nextBody
		if _, err := manager.ResolveNode(t.Context(), "I_1"); err == nil || errors.Is(err, ErrNodeNotFound) {
			t.Fatalf("status %d body %s error = %v", nextStatus, nextBody, err)
		}
	}
}

func TestCompatibilityCredentialsRequireAProvider(t *testing.T) {
	var manager *Manager
	if _, err := manager.SchemaCredential(t.Context()); err == nil {
		t.Fatal("nil manager schema credential")
	}
	if _, err := manager.ResolveNode(t.Context(), "x"); err == nil {
		t.Fatal("nil manager node lookup")
	}
	if _, err := (&Manager{}).GraphQLReadCredential(t.Context(), []Repository{{Owner: "a", Name: "b"}}); err == nil {
		t.Fatal("manager without installation provider returned a read credential")
	}
	if _, err := (&Manager{}).SchemaCredential(t.Context()); err == nil {
		t.Fatal("manager without App returned a schema credential")
	}
}
