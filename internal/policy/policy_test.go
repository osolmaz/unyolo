package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	corepolicy "github.com/osolmaz/brokerkit/policy"
)

func TestPolicyAllowsPRWorkflowButNotDefaultBranchPush(t *testing.T) {
	t.Parallel()
	p := testPolicy(t)

	allowed := []Request{
		repoRequest(OperationGitFetch, "dutifuldev", "gh-broker", nil),
		repoRequest(OperationGitPushBranchCreate, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/bob/work"}),
		repoRequest(OperationGitPushForce, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/agent/work"}),
		repoRequest(OperationPullRequestCreate, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/bob/work", "base_ref": "refs/heads/main"}),
		repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": "README.md"}),
	}
	for _, request := range allowed {
		if decision := p.Evaluate(request); !decision.Allowed {
			t.Fatalf("%s decision = %+v, want allowed", request.Operation, decision)
		}
	}

	decision := p.Evaluate(repoRequest(OperationGitPushForce, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/main"}))
	if decision.Allowed || decision.Effect != EffectDeny {
		t.Fatalf("main push decision = %+v, want deny", decision)
	}
}

func TestPolicyCanAllowDirectMainPushForSpecificRepo(t *testing.T) {
	t.Parallel()
	p := testPolicy(t)
	decision := p.Evaluate(repoRequest(OperationGitPushForce, "dutifuldev", "direct-main", map[string]string{"ref": "refs/heads/main"}))
	if !decision.Allowed || !strings.Contains(strings.Join(decision.MatchedRuleIDs, ","), "direct-main") {
		t.Fatalf("decision = %+v, want direct-main allow", decision)
	}
}

func TestScopeExampleSupportsDefaultPRWorkflow(t *testing.T) {
	t.Parallel()
	p, err := LoadFile(filepath.Join("..", "..", "scope.example.json"))
	if err != nil {
		t.Fatalf("LoadFile(scope.example.json) error = %v", err)
	}

	allowed := []Request{
		{Client: "bob", Operation: OperationInstallationReposList, Target: Target{Kind: "installation"}},
		repoRequest(OperationGitFetch, "osolmaz", "gh-broker", nil),
		repoRequest(OperationGitPushBranchCreate, "osolmaz", "gh-broker", map[string]string{"ref": "refs/heads/bob/work"}),
		repoRequest(OperationGitPushForce, "osolmaz", "gh-broker", map[string]string{"ref": "refs/heads/agent/work"}),
		repoRequest(OperationPullRequestCreate, "osolmaz", "gh-broker", map[string]string{"ref": "refs/heads/bob/work", "base_ref": "refs/heads/main"}),
		repoRequest(OperationGitPushForce, "osolmaz", "direct-main", map[string]string{"ref": "refs/heads/main"}),
	}
	for _, request := range allowed {
		if decision := p.Evaluate(request); !decision.Allowed {
			t.Fatalf("%s decision = %+v, want allowed", request.Operation, decision)
		}
	}

	denied := []Request{
		repoRequest(OperationGitPushForce, "osolmaz", "gh-broker", map[string]string{"ref": "refs/heads/main"}),
		repoRequest(OperationGitRefDelete, "osolmaz", "gh-broker", map[string]string{"ref": "refs/heads/bob/work"}),
	}
	for _, request := range denied {
		if decision := p.Evaluate(request); decision.Allowed {
			t.Fatalf("%s decision = %+v, want denied", request.Operation, decision)
		}
	}
}

func TestPolicyDenyWinsOverAllow(t *testing.T) {
	t.Parallel()
	p := testPolicy(t)
	decision := p.Evaluate(repoRequest(OperationGitPushForce, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/main"}))
	if decision.Allowed || decision.Effect != EffectDeny {
		t.Fatalf("force decision = %+v, want deny", decision)
	}
}

func TestPolicyWildcardTargetMatchesInstallationRequests(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "deny-all",
			Effect:     EffectDeny,
			Clients:    []string{"*"},
			Operations: []Operation{"*"},
			Targets:    []Target{{Kind: "*", Owner: "*", Name: "*"}},
		},
		{
			ID:         "allow-list",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationInstallationReposList},
			Targets:    []Target{{Kind: "installation"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	decision := p.Evaluate(Request{Client: "bob", Operation: OperationInstallationReposList, Target: Target{Kind: "installation"}})
	if decision.Allowed || decision.Effect != EffectDeny {
		t.Fatalf("installation decision = %+v, want wildcard deny to win", decision)
	}
}

func TestPolicyCanScopeContentsReadByRef(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "contents-main",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationContentsRead},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"*"}, "refs": {"main"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allowed := p.Evaluate(repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": "README.md", "ref": "main"}))
	if !allowed.Allowed {
		t.Fatalf("main contents decision = %+v, want allowed", allowed)
	}
	denied := p.Evaluate(repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": "README.md", "ref": "private"}))
	if denied.Allowed {
		t.Fatalf("private contents decision = %+v, want denied", denied)
	}
}

func TestPolicyCanonicalizesHeadRefAlias(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "pr-from-agent-branch",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationPullRequestCreate},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"head_refs": {"refs/heads/agent/*"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allowed := p.Evaluate(repoRequest(OperationPullRequestCreate, "dutifuldev", "gh-broker", map[string]string{"head_refs": "refs/heads/agent/work"}))
	if !allowed.Allowed {
		t.Fatalf("head_refs decision = %+v, want allowed", allowed)
	}
	denied := p.Evaluate(repoRequest(OperationPullRequestCreate, "dutifuldev", "gh-broker", map[string]string{"head_ref": "refs/heads/bob/work"}))
	if denied.Allowed {
		t.Fatalf("other head_ref decision = %+v, want denied", denied)
	}
}

func TestPolicyPathStarDoesNotMatchNestedContent(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "root-files",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationContentsRead},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"*"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rootFile := p.Evaluate(repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": "README.md"}))
	if !rootFile.Allowed {
		t.Fatalf("root file decision = %+v, want allowed", rootFile)
	}
	nestedFile := p.Evaluate(repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": ".github/workflows/ci.yml"}))
	if nestedFile.Allowed {
		t.Fatalf("nested file decision = %+v, want denied", nestedFile)
	}
}

func TestPolicyPreservesPathWhitespaceDuringMatching(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "read-readme",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationContentsRead},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"README.md"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allowed := p.Evaluate(repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": "README.md"}))
	if !allowed.Allowed {
		t.Fatalf("exact path decision = %+v, want allowed", allowed)
	}
	denied := p.Evaluate(repoRequest(OperationContentsRead, "dutifuldev", "gh-broker", map[string]string{"path": " README.md "}))
	if denied.Allowed {
		t.Fatalf("space-padded path decision = %+v, want denied", denied)
	}
}

func TestNormalizeRequestAttrsIgnoresUnknownKeys(t *testing.T) {
	t.Parallel()
	attrs := normalizeRequestAttrs(map[string]string{
		" paths ": " README.md ",
		"unknown": "ignored",
	})
	if attrs["path"] != " README.md " {
		t.Fatalf("path attr = %q, want preserved value", attrs["path"])
	}
	if _, ok := attrs[""]; ok {
		t.Fatalf("attrs include empty canonical key: %#v", attrs)
	}
	if _, ok := attrs["unknown"]; ok || len(attrs) != 1 {
		t.Fatalf("attrs = %#v, want only canonical path", attrs)
	}
}

func TestPolicyListReposUsesInstallationTarget(t *testing.T) {
	t.Parallel()
	p := testPolicy(t)
	decision := p.Evaluate(Request{Client: "bob", Operation: OperationInstallationReposList, Target: Target{Kind: "installation"}})
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want list allowed", decision)
	}
}

func TestPolicyDoesNotMixRules(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{ID: "operation-only", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "other", Name: "*"}}},
		{ID: "target-only", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationContentsRead}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	decision := p.Evaluate(repoRequest(OperationGitFetch, "dutifuldev", "gh-broker", nil))
	if decision.Allowed {
		t.Fatalf("decision = %+v, want denied because one rule must match every dimension", decision)
	}
}

func TestPolicyDeduplicatesRepeatedOperations(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "duplicate-read",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitFetch, OperationGitFetch},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	decision := p.Evaluate(repoRequest(OperationGitFetch, "dutifuldev", "gh-broker", nil))
	if !decision.Allowed || !slices.Equal(decision.MatchedRuleIDs, []string{"duplicate-read"}) {
		t.Fatalf("decision = %+v, want one duplicate-read match", decision)
	}
}

func TestRequestGrantPolicyIsSingleUse(t *testing.T) {
	t.Parallel()
	data, err := corePolicyJSON(Scope{Rules: []Rule{
		{
			ID:         "request-main-update",
			Effect:     EffectRequest,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitPushFastForward},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		},
	}})
	if err != nil {
		t.Fatalf("corePolicyJSON() error = %v", err)
	}
	var doc coreDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0].GrantPolicy == nil {
		t.Fatalf("core rules = %+v, want one request rule with grant policy", doc.Rules)
	}
	grantPolicy := doc.Rules[0].GrantPolicy
	if grantPolicy.DefaultMaxUses != 1 || grantPolicy.MaxUses != 1 {
		t.Fatalf("grant uses = default %d max %d, want 1/1", grantPolicy.DefaultMaxUses, grantPolicy.MaxUses)
	}
}

func TestRequestRulesRequireGrantForExecution(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "request-main-update",
			Effect:     EffectRequest,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitPushForce},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := repoRequest(OperationGitPushForce, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/main"})
	execute := p.Evaluate(request)
	if execute.Allowed || execute.Effect != EffectRequest || execute.GrantPolicy != nil {
		t.Fatalf("Evaluate() = %+v, want approval required but not executable", execute)
	}
	grantRequest := p.EvaluateGrantRequest(request)
	if grantRequest.Allowed || grantRequest.Effect != EffectRequest || grantRequest.GrantPolicy == nil {
		t.Fatalf("EvaluateGrantRequest() = %+v, want requestable grant policy", grantRequest)
	}
}

func TestActiveGrantAllowsExactRequestAndDenyStillWins(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "deny-main",
			Effect:     EffectDeny,
			Clients:    []string{"*"},
			Operations: []Operation{OperationGitPushForce},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	request := repoRequest(OperationGitPushForce, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/main"})
	grant := corepolicy.Grant{
		ID:        "grant-1",
		Client:    "bob",
		Operation: string(OperationGitPushForce),
		Target:    CoreTarget(request.Target),
		Attrs:     request.Attrs,
		ExpiresAt: time.Now().Add(time.Hour),
		UsesLeft:  1,
	}
	if decision := p.Evaluate(request, grant); decision.Allowed || decision.Effect != EffectDeny {
		t.Fatalf("deny-over-grant decision = %+v, want deny", decision)
	}

	empty, err := New(Scope{Rules: []Rule{{
		ID:         "unrelated",
		Effect:     EffectAllow,
		Clients:    []string{"alice"},
		Operations: []Operation{OperationGitFetch},
		Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
	}}})
	if err != nil {
		t.Fatalf("New(empty) error = %v", err)
	}
	allowed := empty.Evaluate(request, grant)
	if !allowed.Allowed || allowed.GrantID != grant.ID || !slices.Equal(allowed.MatchedRuleIDs, []string{grant.ID}) {
		t.Fatalf("active grant decision = %+v, want grant allow", allowed)
	}
	other := empty.Evaluate(repoRequest(OperationGitPushForce, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/other"}), grant)
	if other.Allowed {
		t.Fatalf("other ref decision = %+v, want no grant match", other)
	}
}

func TestFromCoreDecisionUsesGrantRuleIDsWhenAllowIDsEmpty(t *testing.T) {
	t.Parallel()
	decision := fromCoreDecision(corepolicy.Decision{
		Effect:              corepolicy.EffectAllow,
		MatchedGrantRuleIDs: []string{"request-main-update.git.push.fast_forward"},
	})
	if !decision.Allowed || !slices.Equal(decision.MatchedRuleIDs, []string{"request-main-update"}) {
		t.Fatalf("decision = %+v, want original grant rule id", decision)
	}
}

func TestRegistryDeclaresGitHubPolicyCapabilities(t *testing.T) {
	t.Parallel()
	registry := registry()
	repo := registry.Targets["repo"]
	if !repo.Fields["owner"].Required {
		t.Fatal("repo owner field is not required")
	}
	if !repo.Fields["name"].Required {
		t.Fatal("repo name field is not required")
	}

	grantable := []Operation{
		OperationGitPushBranchCreate,
		OperationGitPushFastForward,
		OperationGitPushForce,
		OperationGitRefDelete,
		OperationGitTagUpdate,
		OperationPullRequestCreate,
		OperationPullRequestUpdate,
		OperationPullRequestMerge,
	}
	for _, operation := range grantable {
		spec := registry.Operations[string(operation)]
		if !spec.Grantable {
			t.Fatalf("%s Grantable = false, want true", operation)
		}
		if !slices.Contains(spec.TargetKinds, "repo") {
			t.Fatalf("%s target kinds = %v, want repo", operation, spec.TargetKinds)
		}
	}
	if registry.Operations[string(OperationGitFetch)].Grantable {
		t.Fatal("git.fetch Grantable = true, want false")
	}
}

func TestLoadFileRejectsUnsafeOrUnknownScope(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"empty rules":       `{"rules":[]}`,
		"unknown operation": `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["repo.delete"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}]}]}`,
		"unknown attr":      `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}],"attrs":{"unknown":["x"]}}]}`,
		"incompatible attr": `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["contents.read"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}],"attrs":{"base_refs":["refs/heads/main"]}}]}`,
		"unknown field":     `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}],"extra":true}]}`,
		"deep glob":         `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"**","name":"*"}]}]}`,
		"trailing json":     `{"rules":[{"id":"ok","effect":"allow","clients":["bob"],"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}]}]}{"rules":[]}`,
	}
	for name, body := range cases {
		if _, err := LoadFile(writeScopeFile(t, body)); err == nil {
			t.Fatalf("%s LoadFile() error = nil, want error", name)
		}
	}
}

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := New(Scope{Rules: []Rule{
		{
			ID:         "deny-gh-broker-main-force",
			Effect:     EffectDeny,
			Clients:    []string{"*"},
			Operations: []Operation{OperationGitPushForce},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
		{
			ID:         "deny-ref-delete",
			Effect:     EffectDeny,
			Clients:    []string{"*"},
			Operations: []Operation{OperationGitRefDelete},
			Targets:    []Target{{Kind: "repo", Owner: "*", Name: "*"}},
		},
		{
			ID:         "bob-repo-read",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitFetch, OperationRepoMetadataRead},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
		},
		{
			ID:         "bob-contents-read",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationContentsRead},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
			Attrs:      map[string][]string{"paths": {"*", "docs/*", "."}},
		},
		{
			ID:         "bob-list-repos",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationInstallationReposList},
			Targets:    []Target{{Kind: "installation"}},
		},
		{
			ID:         "bob-push-advertise",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitPushAdvertise},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
		},
		{
			ID:         "bob-push-branches",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitPushBranchCreate, OperationGitPushForce},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/bob/*", "refs/heads/agent/*"}},
		},
		{
			ID:         "bob-pr-create",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationPullRequestCreate},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
			Attrs: map[string][]string{
				"refs":      {"refs/heads/bob/*", "refs/heads/agent/*"},
				"base_refs": {"refs/heads/main"},
			},
		},
		{
			ID:         "direct-main",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{OperationGitPushForce},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "direct-main"}},
			Attrs:      map[string][]string{"refs": {"refs/heads/main"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return p
}

func repoRequest(operation Operation, owner string, name string, attrs map[string]string) Request {
	return Request{Client: "bob", Operation: operation, Target: Target{Kind: "repo", Owner: owner, Name: name}, Attrs: attrs}
}

func writeScopeFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func TestPolicyRequestEffectAndAllowsHelper(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{ID: "request-merge", Effect: EffectRequest, Clients: []string{"bob"}, Operations: []Operation{OperationPullRequestMerge}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}}},
		{ID: "wildcard-read", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{"*"}, Targets: []Target{{Kind: "repo", Owner: "openclaw", Name: "*"}}},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	requestDecision := p.Evaluate(repoRequest(OperationPullRequestMerge, "dutifuldev", "gh-broker", nil))
	if requestDecision.Allowed || requestDecision.Effect != EffectRequest {
		t.Fatalf("request decision = %+v, want request effect", requestDecision)
	}
	if !p.Allows(repoRequest(OperationContentsRead, "openclaw", "openclaw", map[string]string{"path": "README.md"})) {
		t.Fatal("Allows() = false, want wildcard allow")
	}
}

func TestPolicyRejectsIncompleteRequest(t *testing.T) {
	t.Parallel()
	p := testPolicy(t)
	cases := map[string]Request{
		"missing client":     {Operation: OperationGitFetch, Target: Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		"missing operation":  {Client: "bob", Target: Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
		"missing kind":       {Client: "bob", Operation: OperationGitFetch},
		"missing repo owner": {Client: "bob", Operation: OperationGitPushForce, Target: Target{Kind: "repo", Name: "gh-broker"}, Attrs: map[string]string{"ref": "refs/heads/main"}},
		"missing repo name":  {Client: "bob", Operation: OperationGitPushForce, Target: Target{Kind: "repo", Owner: "dutifuldev"}, Attrs: map[string]string{"ref": "refs/heads/main"}},
	}
	for name, request := range cases {
		decision := p.Evaluate(request)
		if decision.Allowed || decision.Reason != "request is incomplete" {
			t.Fatalf("%s decision = %+v, want incomplete denial", name, decision)
		}
	}
}

func TestAllGitHubGrantableOperationsCanRequest(t *testing.T) {
	t.Parallel()
	operations := []Operation{
		OperationGitPushBranchCreate,
		OperationGitPushFastForward,
		OperationGitPushForce,
		OperationGitRefDelete,
		OperationGitTagUpdate,
		OperationPullRequestCreate,
		OperationPullRequestUpdate,
		OperationPullRequestMerge,
	}
	for _, operation := range operations {
		p, err := New(Scope{Rules: []Rule{
			{
				ID:         "request-" + string(operation),
				Effect:     EffectRequest,
				Clients:    []string{"bob"},
				Operations: []Operation{operation},
				Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			},
		}})
		if err != nil {
			t.Fatalf("%s New() error = %v", operation, err)
		}
		decision := p.Evaluate(repoRequest(operation, "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/main"}))
		if decision.Allowed || decision.Effect != EffectRequest {
			t.Fatalf("%s decision = %+v, want request effect", operation, decision)
		}
	}
}

func TestPolicyValidationRejectsMoreInvalidRules(t *testing.T) {
	t.Parallel()
	cases := map[string]Scope{
		"duplicate id": {Rules: []Rule{
			{ID: "dup", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}},
			{ID: "dup", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationContentsRead}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}},
		}},
		"bad effect":        {Rules: []Rule{{ID: "bad", Effect: Effect("maybe"), Clients: []string{"bob"}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}}}},
		"empty client":      {Rules: []Rule{{ID: "bad", Effect: EffectAllow, Clients: []string{""}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}}}},
		"bad target kind":   {Rules: []Rule{{ID: "bad", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "org", Owner: "dutifuldev", Name: "*"}}}}},
		"missing repo name": {Rules: []Rule{{ID: "bad", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev"}}}}},
	}
	for name, scope := range cases {
		if _, err := New(scope); err == nil {
			t.Fatalf("%s New() error = nil, want error", name)
		}
	}
}
