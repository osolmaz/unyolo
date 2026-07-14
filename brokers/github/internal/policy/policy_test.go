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
		repoRequest(Operation("pull_request.create"), "dutifuldev", "gh-broker", map[string]string{"ref": "refs/heads/bob/work", "base_ref": "refs/heads/main"}),
		repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": "README.md"}),
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

func TestScopeExampleSeparatesDirectAndApprovalOperations(t *testing.T) {
	t.Parallel()
	p, err := LoadFile(filepath.Join("..", "..", "scope.example.json"))
	if err != nil {
		t.Fatalf("LoadFile(scope.example.json) error = %v", err)
	}

	allowed := []Request{
		repoRequest(OperationGitFetch, "osolmaz", "brokerkit", nil),
		repoRequest(Operation("repo.contents.read"), "osolmaz", "brokerkit", nil),
		repoRequest(OperationGitPushBranchCreate, "osolmaz", "brokerkit", map[string]string{"ref": "refs/heads/bob/work"}),
		repoRequest(OperationGitPushForce, "osolmaz", "brokerkit", map[string]string{"ref": "refs/heads/agent/work"}),
	}
	for _, request := range allowed {
		if decision := p.Evaluate(request); !decision.Allowed {
			t.Fatalf("%s decision = %+v, want allowed", request.Operation, decision)
		}
	}

	denied := []Request{
		repoRequest(OperationGitPushForce, "osolmaz", "brokerkit", map[string]string{"ref": "refs/heads/main"}),
		repoRequest(OperationGitRefDelete, "osolmaz", "brokerkit", map[string]string{"ref": "refs/heads/bob/work"}),
		repoRequest(OperationGitFetch, "osolmaz", "other", nil),
	}
	for _, request := range denied {
		if decision := p.Evaluate(request); decision.Allowed {
			t.Fatalf("%s decision = %+v, want denied", request.Operation, decision)
		}
	}

	requested := []Request{
		repoRequest(Operation("pull_request.create"), "osolmaz", "brokerkit", map[string]string{"ref": "refs/heads/bob/work", "base_ref": "refs/heads/main"}),
		repoRequest(Operation("repo.delete"), "osolmaz", "brokerkit-e2e-123", nil),
		repoRequest(Operation("agent_task.create_or_update_repo_secret"), "osolmaz", "brokerkit", nil),
		repoRequest(Operation("collaborator.repos_add_collaborator"), "osolmaz", "brokerkit", nil),
	}
	for _, request := range requested {
		if decision := p.Evaluate(request); decision.Effect != EffectRequest || decision.Allowed {
			t.Fatalf("%s decision = %+v, want approval request", request.Operation, decision)
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
			Operations: []Operation{Operation("installation.repo.list")},
			Targets:    []Target{{Kind: "installation"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	decision := p.Evaluate(Request{Client: "bob", Operation: Operation("installation.repo.list"), Target: Target{Kind: "installation"}})
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
			Operations: []Operation{Operation("repo.contents.read")},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"*"}, "refs": {"main"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allowed := p.Evaluate(repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": "README.md", "ref": "main"}))
	if !allowed.Allowed {
		t.Fatalf("main contents decision = %+v, want allowed", allowed)
	}
	denied := p.Evaluate(repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": "README.md", "ref": "private"}))
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
			Operations: []Operation{Operation("pull_request.create")},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"head_refs": {"refs/heads/agent/*"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allowed := p.Evaluate(repoRequest(Operation("pull_request.create"), "dutifuldev", "gh-broker", map[string]string{"head_refs": "refs/heads/agent/work"}))
	if !allowed.Allowed {
		t.Fatalf("head_refs decision = %+v, want allowed", allowed)
	}
	denied := p.Evaluate(repoRequest(Operation("pull_request.create"), "dutifuldev", "gh-broker", map[string]string{"head_ref": "refs/heads/bob/work"}))
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
			Operations: []Operation{Operation("repo.contents.read")},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"*"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	rootFile := p.Evaluate(repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": "README.md"}))
	if !rootFile.Allowed {
		t.Fatalf("root file decision = %+v, want allowed", rootFile)
	}
	nestedFile := p.Evaluate(repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": ".github/workflows/ci.yml"}))
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
			Operations: []Operation{Operation("repo.contents.read")},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}},
			Attrs:      map[string][]string{"paths": {"README.md"}},
		},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	allowed := p.Evaluate(repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": "README.md"}))
	if !allowed.Allowed {
		t.Fatalf("exact path decision = %+v, want allowed", allowed)
	}
	denied := p.Evaluate(repoRequest(Operation("repo.contents.read"), "dutifuldev", "gh-broker", map[string]string{"path": " README.md "}))
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

func TestIncompleteRequest(t *testing.T) {
	t.Parallel()
	if !incompleteRequest(Request{}) {
		t.Fatal("incompleteRequest(empty) = false, want true")
	}
	if !incompleteRequest(Request{Client: "bob", Operation: OperationGitFetch, Target: Target{Kind: "repo", Owner: "dutifuldev"}}) {
		t.Fatal("incompleteRequest(missing repo name) = false, want true")
	}
	if incompleteRequest(Request{Client: "bob", Operation: Operation("installation.repo.list"), Target: Target{Kind: "installation"}}) {
		t.Fatal("incompleteRequest(installation list) = true, want false")
	}
	if incompleteRequest(repoRequest(OperationGitFetch, "dutifuldev", "gh-broker", nil)) {
		t.Fatal("incompleteRequest(repo fetch) = true, want false")
	}
}

func TestRegistryHelpers(t *testing.T) {
	t.Parallel()
	ops := allOperations()
	if !slices.Contains(ops, OperationGitFetch) || !slices.Contains(ops, OperationWebhookGitHubReceive) {
		t.Fatalf("allOperations() = %v, want known GitHub operations", ops)
	}
	if !slices.IsSorted(ops) {
		t.Fatalf("allOperations() = %v, want sorted operations", ops)
	}
	if attrs := operationAttrs(Operation("pull_request.create")); !slices.Contains(attrs, "ref") || !slices.Contains(attrs, "base_ref") || !slices.Contains(attrs, "head_ref") {
		t.Fatalf("operationAttrs(pull_request.create) = %v, want generated policy attrs", attrs)
	}
	if got := targetKindForOperation(Operation("installation.repo.list")); got != "installation" {
		t.Fatalf("targetKindForOperation(installation.repos.list) = %q, want installation", got)
	}
	if got := targetKindForOperation(OperationGitFetch); got != "repo" {
		t.Fatalf("targetKindForOperation(git.fetch) = %q, want repo", got)
	}
}

func TestCoreTargetsForOperation(t *testing.T) {
	t.Parallel()
	targets, err := coreTargetsForOperation([]Target{{Kind: "*", Owner: "dutifuldev", Name: "gh-broker"}}, OperationGitFetch)
	if err != nil {
		t.Fatalf("coreTargetsForOperation(repo) error = %v", err)
	}
	if len(targets) != 1 || targets[0]["kind"] != "repo" || targets[0]["owner"] != "dutifuldev" {
		t.Fatalf("repo targets = %+v, want repo target", targets)
	}
	installTargets, err := coreTargetsForOperation([]Target{{Kind: "*"}}, Operation("installation.repo.list"))
	if err != nil {
		t.Fatalf("coreTargetsForOperation(installation) error = %v", err)
	}
	if len(installTargets) != 1 || installTargets[0]["kind"] != "installation" {
		t.Fatalf("installation targets = %+v, want installation target", installTargets)
	}
	if _, err := coreTargetsForOperation([]Target{{Kind: "installation"}}, OperationGitFetch); err == nil {
		t.Fatal("coreTargetsForOperation(incompatible) error = nil, want error")
	}
}

func TestAttrsForOperation(t *testing.T) {
	t.Parallel()
	attrs, err := attrsForOperation(map[string][]string{"refs": {"refs/heads/main"}}, OperationGitPushForce)
	if err != nil {
		t.Fatalf("attrsForOperation() error = %v", err)
	}
	if !slices.Equal(attrs["ref"], []string{"refs/heads/main"}) {
		t.Fatalf("attrs = %+v, want canonical ref", attrs)
	}
	if _, err := attrsForOperation(map[string][]string{"path": {"README.md"}}, OperationGitFetch); err == nil {
		t.Fatal("attrsForOperation(unsupported attr) error = nil, want error")
	}
}

func TestExpandedRuleID(t *testing.T) {
	t.Parallel()
	if got := expandedRuleID("rule", OperationGitFetch, 2); got != "rule.git.fetch" {
		t.Fatalf("expandedRuleID() = %q, want operation suffix", got)
	}
	if got := expandedRuleID("rule", OperationGitFetch, 1); got != "rule" {
		t.Fatalf("expandedRuleID(single) = %q, want original id", got)
	}
}

func TestPolicyListReposUsesInstallationTarget(t *testing.T) {
	t.Parallel()
	p := testPolicy(t)
	decision := p.Evaluate(Request{Client: "bob", Operation: Operation("installation.repo.list"), Target: Target{Kind: "installation"}})
	if !decision.Allowed {
		t.Fatalf("decision = %+v, want list allowed", decision)
	}
}

func TestPolicyDoesNotMixRules(t *testing.T) {
	t.Parallel()
	p, err := New(Scope{Rules: []Rule{
		{ID: "operation-only", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{OperationGitFetch}, Targets: []Target{{Kind: "repo", Owner: "other", Name: "*"}}},
		{ID: "target-only", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{Operation("repo.contents.read")}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}},
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
		Attrs:     corepolicy.SingletonValues(request.Attrs),
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
	if got := originalRuleID("request-main-update.git.push.force"); got != "request-main-update" {
		t.Fatalf("originalRuleID() = %q, want stripped operation suffix", got)
	}
	if got := originalRuleID("already-original"); got != "already-original" {
		t.Fatalf("originalRuleID(plain) = %q, want unchanged id", got)
	}
}

func TestDecisionReasons(t *testing.T) {
	t.Parallel()
	if got := allowReason(corepolicy.Decision{}); got != "allowed by policy" {
		t.Fatalf("allowReason(policy) = %q, want policy reason", got)
	}
	if got := allowReason(corepolicy.Decision{GrantID: "grant-1"}); got != "allowed by grant" {
		t.Fatalf("allowReason(grant) = %q, want grant reason", got)
	}
	for _, reason := range []string{"", "policy_denied"} {
		if got := denyReason(corepolicy.Decision{Reason: reason}); got != "denied by policy" {
			t.Fatalf("denyReason(%q) = %q, want policy denial", reason, got)
		}
	}
	if got := denyReason(corepolicy.Decision{Reason: "custom reason"}); got != "custom reason" {
		t.Fatalf("denyReason(custom) = %q, want custom reason", got)
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

	repoGrantable := []Operation{
		OperationGitPushBranchCreate,
		OperationGitPushFastForward,
		OperationGitPushForce,
		OperationGitRefDelete,
		OperationGitTagUpdate,
		Operation("pull_request.create"),
	}
	for _, operation := range repoGrantable {
		spec := registry.Operations[string(operation)]
		if !spec.Grantable {
			t.Fatalf("%s Grantable = false, want true", operation)
		}
		if !slices.Contains(spec.TargetKinds, "repo") {
			t.Fatalf("%s target kinds = %v, want repo", operation, spec.TargetKinds)
		}
	}
	for _, operation := range []Operation{Operation("pull_request.update"), Operation("pull_request.merge")} {
		spec := registry.Operations[string(operation)]
		if !spec.Grantable || !slices.Contains(spec.TargetKinds, "pull_request") {
			t.Fatalf("%s spec = %+v, want grantable pull_request", operation, spec)
		}
	}
	if registry.Operations[string(OperationGitFetch)].Grantable {
		t.Fatal("git.fetch Grantable = true, want false")
	}
}

func TestLoadFileRejectsUnsafeOrUnknownScope(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"missing rules":     `{}`,
		"null rules":        `{"rules":null}`,
		"unknown operation": `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["github.raw.request"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}]}]}`,
		"unknown attr":      `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}],"attrs":{"unknown":["x"]}}]}`,
		"incompatible attr": `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"dutifuldev","name":"*"}],"attrs":{"base_refs":["refs/heads/main"]}}]}`,
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

func TestLoadFileAcceptsExplicitDenyAllScope(t *testing.T) {
	t.Parallel()
	policy, err := LoadFile(writeScopeFile(t, `{"rules":[]}`))
	if err != nil {
		t.Fatalf("LoadFile(empty rules) error = %v", err)
	}
	decision := policy.Evaluate(Request{
		Client:    "bob",
		Operation: OperationGitFetch,
		Target:    Target{Kind: "repo", Owner: "dutifuldev", Name: "demo"},
	})
	if decision.Allowed || decision.Effect != EffectNoMatch {
		t.Fatalf("empty rules decision = %+v, want deny-all no-match", decision)
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
			Operations: []Operation{OperationGitFetch, Operation("repo.metadata.read")},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
		},
		{
			ID:         "bob-contents-read",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{Operation("repo.contents.read")},
			Targets:    []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}},
			Attrs:      map[string][]string{"paths": {"*", "docs/*", "."}},
		},
		{
			ID:         "bob-list-repos",
			Effect:     EffectAllow,
			Clients:    []string{"bob"},
			Operations: []Operation{Operation("installation.repo.list")},
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
			Operations: []Operation{Operation("pull_request.create")},
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
		{ID: "request-merge", Effect: EffectRequest, Clients: []string{"bob"}, Operations: []Operation{Operation("pull_request.merge")}, Targets: []Target{{Kind: "pull_request", Owner: "dutifuldev", Name: "gh-broker", Number: 7}}},
		{ID: "wildcard-read", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{"*"}, Targets: []Target{{Kind: "repo", Owner: "openclaw", Name: "*"}}},
	}})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	requestDecision := p.Evaluate(Request{Client: "bob", Operation: Operation("pull_request.merge"), Target: Target{Kind: "pull_request", Owner: "dutifuldev", Name: "gh-broker", Number: 7}})
	if requestDecision.Allowed || requestDecision.Effect != EffectRequest {
		t.Fatalf("request decision = %+v, want request effect", requestDecision)
	}
	if !p.Allows(repoRequest(Operation("repo.contents.read"), "openclaw", "openclaw", map[string]string{"path": "README.md"})) {
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
		Operation("pull_request.create"),
		Operation("pull_request.update"),
		Operation("pull_request.merge"),
	}
	for _, operation := range operations {
		target := Target{Kind: "repo", Owner: "dutifuldev", Name: "gh-broker"}
		if targetKindForOperation(operation) == "pull_request" {
			target = Target{Kind: "pull_request", Owner: "dutifuldev", Name: "gh-broker", Number: 7}
		}
		p, err := New(Scope{Rules: []Rule{
			{
				ID:         "request-" + string(operation),
				Effect:     EffectRequest,
				Clients:    []string{"bob"},
				Operations: []Operation{operation},
				Targets:    []Target{target},
			},
		}})
		if err != nil {
			t.Fatalf("%s New() error = %v", operation, err)
		}
		decision := p.Evaluate(Request{Client: "bob", Operation: operation, Target: target, Attrs: map[string]string{"ref": "refs/heads/main"}})
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
			{ID: "dup", Effect: EffectAllow, Clients: []string{"bob"}, Operations: []Operation{Operation("repo.contents.read")}, Targets: []Target{{Kind: "repo", Owner: "dutifuldev", Name: "*"}}},
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
