package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/budget"
)

func TestParseRejectsLegacyScopeFormat(t *testing.T) {
	_, err := Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset"}]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown field", err)
	}
}

func TestParseRejectsBoundaryWhitespaceRuleID(t *testing.T) {
	_, err := Parse([]byte(`{"rules":[{
		"id":" rule","effect":"allow","clients":["agent"],
		"operations":["repo.contents.read"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`))
	if err == nil || !strings.Contains(err.Error(), ".id") {
		t.Fatalf("Parse(boundary whitespace id) error = %v, want id validation error", err)
	}
}

func TestDecideAllowDenyAndNoMatch(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "append-datasets",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "*"}]
			},
			{
				"id": "deny-secret",
				"effect": "deny",
				"clients": ["*"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "secret"}]
			}
		]
	}`)

	allowed := pol.Decide(repoReq("agent", OpGitPushAppend, "dataset", "acme", "public", ""), nil, time.Now(), false)
	if allowed.Effect != EffectAllow || allowed.Reason != "policy_allowed" || strings.Join(allowed.MatchedAllowRuleIDs, ",") != "append-datasets" {
		t.Fatalf("allowed decision = %+v", allowed)
	}
	denied := pol.Decide(repoReq("agent", OpGitPushAppend, "dataset", "acme", "secret", ""), nil, time.Now(), false)
	if denied.Effect != EffectDeny || denied.Reason != "policy_denied" || strings.Join(denied.MatchedDenyRuleIDs, ",") != "deny-secret" {
		t.Fatalf("denied decision = %+v", denied)
	}
	noMatch := pol.Decide(repoReq("other", OpGitPushAppend, "dataset", "acme", "public", ""), nil, time.Now(), false)
	if noMatch.Effect != EffectNoMatch || noMatch.Reason != "no_matching_rule" {
		t.Fatalf("no match decision = %+v", noMatch)
	}
}

func TestKernelRepositoryRulesAreSupported(t *testing.T) {
	pol := mustParse(t, `{"rules":[{
		"id":"deny-kernel-delete",
		"effect":"deny",
		"clients":["agent"],
		"operations":["repo.delete"],
		"targets":[{"kind":"repo","type":"kernel","owner":"acme","name":"demo"}]
	}]}`)
	request := repoReq("agent", Operation("repo.delete"), "kernel", "acme", "demo", "")
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("kernel request validation error = %v", err)
	}
	if decision := pol.Decide(request, nil, time.Now(), false); decision.Effect != EffectDeny {
		t.Fatalf("kernel decision = %+v", decision)
	}
}

func TestBucketListAllowsExactNamespaceWildcardTarget(t *testing.T) {
	t.Parallel()
	request := Request{Client: "agent", Operation: Operation("bucket.list"),
		Target: Target{Kind: KindBucket, Owner: "acme", Name: "*"}}
	if err := ValidateRequest(request); err != nil {
		t.Fatalf("bucket list request validation error = %v", err)
	}
	policy := mustParse(t, `{"rules":[{"id":"list-buckets","effect":"allow","clients":["agent"],"operations":["bucket.list"],"targets":[{"kind":"bucket","owner":"acme","name":"*"}]}]}`)
	if decision := policy.Decide(request, nil, time.Now(), false); decision.Effect != EffectAllow {
		t.Fatalf("bucket list decision = %+v", decision)
	}
}

func TestWildcardListTargetValidation(t *testing.T) {
	t.Parallel()
	if err := validateRepoListTarget(Target{Type: TypeDataset, Owner: "acme"}); err != nil {
		t.Fatalf("valid repository list target = %v", err)
	}
	if err := validateRepoListTarget(Target{Type: TypeAny, Owner: "*"}); err == nil {
		t.Fatal("invalid repository list target succeeded")
	}
	if err := validateBucketListTarget(Target{Owner: "acme"}); err != nil {
		t.Fatalf("valid bucket list target = %v", err)
	}
	if err := validateBucketListTarget(Target{Owner: "*"}); err == nil {
		t.Fatal("invalid bucket list target succeeded")
	}
}

func TestRequestableDoesNotMeanExecutable(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "request-read",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["repo.contents.read"],
				"targets": [{"kind": "repo", "type": "*", "owner": "*", "name": "*"}],
				"grant_policy": {"default_minutes": 5, "max_minutes": 15}
			}
		]
	}`)

	exec := pol.Decide(repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), false)
	if exec.Effect != EffectDeny || exec.Reason != "approval_required" {
		t.Fatalf("execution decision = %+v", exec)
	}
	request := pol.Decide(repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), true)
	if request.Effect != EffectRequest || request.Reason != "requestable" || request.GrantPolicy == nil || request.GrantPolicy.MaxMinutes != 15 {
		t.Fatalf("grant-request decision = %+v", request)
	}
}

func TestClientNamesAreLiteralExceptWildcard(t *testing.T) {
	pol := mustParse(t, `{"rules":[{
		"id":"literal-client",
		"effect":"allow",
		"clients":["agent-*"],
		"operations":["repo.contents.read"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`)
	if got := pol.Decide(repoReq("agent-*", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("literal client decision = %+v, want allow", got)
	}
	if got := pol.Decide(repoReq("agent-prod", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("glob-like client decision = %+v, want no_match", got)
	}
}

func TestDistinctLiteralClientNamesDoNotOverlap(t *testing.T) {
	pol := mustParse(t, `{"rules":[
		{
			"id":"first-literal-client",
			"effect":"request",
			"clients":["agent-*"],
			"operations":["repo.contents.read"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
			"grant_policy":{"default_minutes":5,"max_minutes":5}
		},
		{
			"id":"second-literal-client",
			"effect":"request",
			"clients":["agent-*x"],
			"operations":["repo.contents.read"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}],
			"grant_policy":{"default_minutes":5,"max_minutes":5}
		}
	]}`)

	first := pol.Decide(repoReq("agent-*", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), true)
	if first.Effect != EffectRequest || strings.Join(first.MatchedRequestRuleIDs, ",") != "first-literal-client" {
		t.Fatalf("first literal client decision = %+v, want first request rule", first)
	}
	second := pol.Decide(repoReq("agent-*x", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), true)
	if second.Effect != EffectRequest || strings.Join(second.MatchedRequestRuleIDs, ",") != "second-literal-client" {
		t.Fatalf("second literal client decision = %+v, want second request rule", second)
	}
}

func TestEmbeddedDoubleStarPathGrammarIsPreserved(t *testing.T) {
	pol := mustParse(t, `{"rules":[{
		"id":"json-paths",
		"effect":"allow",
		"clients":["agent"],
		"operations":["repo.contents.read"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","paths":["artifacts/**.json"]}]
	}]}`)
	request := repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", "")
	request.Target.Paths = []string{"artifacts/nested/result.json"}
	if got := pol.Decide(request, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("embedded ** decision = %+v, want allow", got)
	}
}

func TestListingDoesNotAllowContentsOrPush(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "list",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["repo.list", "repo.metadata.read"],
				"targets": [{"kind": "repo", "type": "*", "owner": "*", "name": "*"}]
			}
		]
	}`)
	if got := pol.Decide(repoReq("agent", OpRepoList, "dataset", "acme", "repo", ""), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("list decision = %+v", got)
	}
	if got := pol.Decide(repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("contents decision = %+v", got)
	}
	if got := pol.Decide(repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/main"), nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("push decision = %+v", got)
	}
}

func TestRepoRefsOnlyConstrainPushOperations(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "read-with-ref",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["repo.contents.read", "git.fetch"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}]
			},
			{
				"id": "append-main",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}]
			}
		]
	}`)
	if got := pol.Decide(repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("content read decision = %+v", got)
	}
	if got := pol.Decide(repoReq("agent", OpGitFetch, "dataset", "acme", "repo", ""), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("fetch decision = %+v", got)
	}
	if got := pol.Decide(repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/main"), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("main push decision = %+v", got)
	}
	if got := pol.Decide(repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/dev"), nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("dev push decision = %+v", got)
	}
	refLessSupport := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "")
	refLessSupport.IgnoreRepoRefs = true
	if got := pol.Decide(refLessSupport, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("ref-less support decision = %+v", got)
	}
}

func TestRefLessRequestKeepsOriginalGrantPolicy(t *testing.T) {
	pol := mustParse(t, `{"rules":[{
		"id":"request-main",
		"effect":"request",
		"clients":["agent"],
		"operations":["git.push.append"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":["refs/heads/main"]}],
		"grant_policy":{"mode":"execution","default_minutes":3,"max_minutes":13,"request_ttl_minutes":4,"default_max_uses":1,"max_uses":1}
	}]}`)
	req := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "")
	req.IgnoreRepoRefs = true
	decision := pol.Decide(req, nil, time.Now(), true)
	if decision.Effect != EffectRequest || decision.GrantPolicy == nil {
		t.Fatalf("ref-less request decision = %+v, want requestable", decision)
	}
	if decision.GrantPolicy.Mode != GrantModeExecution ||
		decision.GrantPolicy.DefaultMinutes != 3 ||
		decision.GrantPolicy.MaxMinutes != 13 ||
		decision.GrantPolicy.RequestTTLMinutes != 4 {
		t.Fatalf("ref-less grant policy = %+v, want original rule bounds", decision.GrantPolicy)
	}
}

func TestRefLessSupportRequestMatchesActiveGrant(t *testing.T) {
	pol := mustParse(t, `{"rules":[]}`)
	expires := time.Now().Add(time.Minute)
	target := Target{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}
	grant := GeneratedGrantRule("grant", "agent", OpGitPushAppend, target, expires, 1)
	grant.Attrs = map[string]AttrConstraint{"ref_change": {Values: []string{"fast_forward"}}}
	request := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "")
	request.IgnoreRepoRefs = true
	decision := pol.Decide(request, []Rule{grant}, time.Now(), false)
	if decision.Effect != EffectAllow || decision.GrantID != "grant" {
		t.Fatalf("ref-less support decision = %+v, want active grant", decision)
	}
}

func TestActiveGrantRefChangeValuesUseOrSemantics(t *testing.T) {
	pol := mustParse(t, `{"rules":[]}`)
	target := Target{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"}}
	grant := GeneratedGrantRule("grant", "agent", OpGitPushAppend, target, time.Now().Add(time.Minute), 1)
	grant.Attrs = map[string]AttrConstraint{"ref_change": {Values: []string{"create", "fast_forward"}}}
	request := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/main")
	request.Attrs = map[string]any{"ref_change": "fast_forward"}

	decision := pol.Decide(request, []Rule{grant}, time.Now(), false)
	if decision.Effect != EffectAllow || decision.GrantID != "grant" {
		t.Fatalf("multi-value ref-change grant decision = %+v, want grant allow", decision)
	}
}

func TestReceivePackDiscoveryDecision(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "deny-main-ref-only",
				"effect": "deny",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}]
			},
			{
				"id": "deny-create-attr-only",
				"effect": "deny",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
				"attrs": {"ref_change": "create"}
			},
			{
				"id": "allow-main",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}]
			}
		]
	}`)
	req := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "")
	if got := pol.DecideReceivePackDiscovery(req, nil, time.Now()); got.Effect != EffectAllow {
		t.Fatalf("discovery with ref-scoped deny and allow = %+v, want allow", got)
	}

	broadDeny := mustParse(t, `{"rules":[{
		"id":"deny-repo",
		"effect":"deny",
		"clients":["agent"],
		"operations":["git.push.append"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`)
	if got := broadDeny.DecideReceivePackDiscovery(req, nil, time.Now()); got.Effect != EffectDeny {
		t.Fatalf("broad deny discovery = %+v, want deny", got)
	}

	empty := mustParse(t, `{"rules":[]}`)
	grant := GeneratedGrantRule("grant", "agent", OpGitPushAppend, Target{
		Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"},
	}, time.Now().Add(time.Minute), 1)
	maxBytes := int64(10)
	grant.Attrs = map[string]AttrConstraint{
		"max_bytes":  {Number: &maxBytes},
		"ref_change": {Values: []string{"fast_forward"}},
	}
	if got := empty.DecideReceivePackDiscovery(req, []Rule{grant}, time.Now()); got.Effect != EffectAllow || got.Reason != "grant_allowed" {
		t.Fatalf("discovery with constrained active grant = %+v, want grant allow", got)
	}
}

func TestAttrValuesMatchAndConstraints(t *testing.T) {
	approved := map[string]any{
		"ref_change": []string{"fast_forward", "create"},
		"max_bytes":  int64(10),
	}
	actual := map[string]any{"ref_change": "fast_forward", "max_bytes": int64(9)}
	if !AttrValuesMatch(approved, actual) {
		t.Fatalf("AttrValuesMatch() = false, want true")
	}
	actual["max_bytes"] = int64(11)
	if AttrValuesMatch(approved, actual) {
		t.Fatalf("AttrValuesMatch() = true for too-large max_bytes, want false")
	}
	if _, err := AttrConstraintsFromValues(map[string]any{"unknown": "value"}); err == nil {
		t.Fatalf("AttrConstraintsFromValues() unknown attr error = nil")
	}
	if _, err := AttrConstraintsFromValues(map[string]any{"ref_change": map[string]any{"bad": "shape"}}); err == nil {
		t.Fatalf("AttrConstraintsFromValues() bad attr shape error = nil")
	}
	if _, err := AttrConstraintsFromValues(map[string]any{"max_bytes": "10"}); err == nil {
		t.Fatalf("AttrConstraintsFromValues() string max_bytes error = nil")
	}
	if _, err := AttrConstraintsFromValues(map[string]any{"ref_change": "non-fast-forward"}); err == nil {
		t.Fatalf("AttrConstraintsFromValues() bad ref_change error = nil")
	}
}

func TestLoadFileAndRulesClone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, []byte(`{"rules":[{
		"id":"allow-fetch",
		"effect":"allow",
		"clients":["agent"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	rules := pol.Rules()
	if len(rules) != 1 || rules[0].ID != "allow-fetch" {
		t.Fatalf("Rules() = %+v, want allow-fetch", rules)
	}
	rules[0].ID = "mutated"
	if got := pol.Rules()[0].ID; got != "allow-fetch" {
		t.Fatalf("Rules() exposed backing slice, got id %q", got)
	}
}

func TestParseRejectsInvalidAttrValues(t *testing.T) {
	cases := []struct {
		name  string
		attrs string
	}{
		{name: "string max bytes", attrs: `"max_bytes":"10"`},
		{name: "unknown ref change", attrs: `"ref_change":"non-fast-forward"`},
		{name: "numeric ref change", attrs: `"ref_change":1`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(`{
				"rules": [{
					"id": "bad-attrs",
					"effect": "deny",
					"clients": ["agent"],
					"operations": ["git.push.force"],
					"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
					"attrs": {` + tc.attrs + `}
				}]
			}`))
			if err == nil {
				t.Fatal("Parse() error = nil, want invalid attrs error")
			}
		})
	}
}

func TestWildcardRuleRejectsMalformedConcreteRepoTarget(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "wildcard-read",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["repo.contents.read"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "*", "name": "*"}]
		}]
	}`)
	for _, target := range []Target{
		{Kind: KindRepo, Type: TypeDataset, Owner: "..", Name: "repo"},
		{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: ".."},
		{Kind: KindRepo, Type: TypeDataset, Owner: "acme/bad", Name: "repo"},
	} {
		got := pol.Decide(Request{Client: "agent", Operation: OpRepoContentsRead, Target: target}, nil, time.Now(), false)
		if got.Effect != EffectDeny || got.Reason != "invalid_target" {
			t.Fatalf("decision for malformed target %+v = %+v, want invalid_target", target, got)
		}
	}
}

func TestGeneratedGrantAllowsOnlyExactClientAndDenyStillWins(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "deny-main",
				"effect": "deny",
				"clients": ["*"],
				"operations": ["git.push.force"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}]
			}
		]
	}`)
	grant := GeneratedGrantRule("grant_1", "agent", OpGitPushForce, Target{
		Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "repo", Refs: []string{"refs/heads/main"},
	}, time.Now().Add(time.Minute), 1)
	req := repoReq("agent", OpGitPushForce, "dataset", "acme", "repo", "refs/heads/main")
	if got := pol.Decide(req, []Rule{grant}, time.Now(), false); got.Effect != EffectDeny || got.Reason != "policy_denied" {
		t.Fatalf("deny-over-grant decision = %+v", got)
	}

	empty := mustParse(t, `{"rules":[]}`)
	if got := empty.Decide(req, []Rule{grant}, time.Now(), false); got.Effect != EffectAllow || got.Reason != "grant_allowed" || got.GrantID != "grant_1" {
		t.Fatalf("grant decision = %+v", got)
	}
	if got := empty.Decide(repoReq("other", OpGitPushForce, "dataset", "acme", "repo", "refs/heads/main"), []Rule{grant}, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("other client decision = %+v", got)
	}
	if got := empty.Decide(req, []Rule{GeneratedGrantRule("grant_2", "agent", OpGitPushForce, req.Target, time.Now().Add(-time.Second), 1)}, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("expired grant decision = %+v", got)
	}
	if got := empty.Decide(req, []Rule{GeneratedGrantRule("grant_3", "agent", OpGitPushForce, req.Target, time.Now().Add(time.Minute), 0)}, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("consumed grant decision = %+v", got)
	}
}

func TestGeneratedGrantPreservesNumericCeiling(t *testing.T) {
	pol := mustParse(t, `{"rules":[]}`)
	request := repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", "")
	request.Attrs = map[string]any{"max_bytes": int64(5)}
	grant := GeneratedGrantRule("grant_max", "agent", OpRepoContentsRead, request.Target, time.Now().Add(time.Minute), 1)
	maximum := int64(10)
	grant.Attrs = map[string]AttrConstraint{"max_bytes": {Number: &maximum}}
	if got := pol.Decide(request, []Rule{grant}, time.Now(), false); got.Effect != EffectAllow || got.GrantID != "grant_max" {
		t.Fatalf("bounded grant decision = %+v, want grant allow", got)
	}
	request.Attrs["max_bytes"] = int64(11)
	if got := pol.Decide(request, []Rule{grant}, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("over-limit grant decision = %+v, want no_match", got)
	}
}

func TestOverlappingRequestRules(t *testing.T) {
	samePolicy := `{
		"rules": [
			{
				"id": "request-all",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["repo.contents.read"],
				"targets": [{"kind": "repo", "type": "*", "owner": "acme", "name": "*"}],
				"grant_policy": {"default_minutes": 5, "max_minutes": 15}
			},
			{
				"id": "request-one",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["repo.contents.read"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
				"grant_policy": {"default_minutes": 5, "max_minutes": 15}
			}
		]
	}`
	if _, err := Parse([]byte(samePolicy)); err != nil {
		t.Fatalf("Parse(samePolicy) error = %v", err)
	}

	differentPolicy := strings.Replace(samePolicy, `"max_minutes": 15}`, `"max_minutes": 20}`, 1)
	if _, err := Parse([]byte(differentPolicy)); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("Parse(differentPolicy) error = %v, want overlap", err)
	}

	disjointRefs := `{
		"rules": [
			{
				"id": "request-main",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["git.push.force"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}],
				"grant_policy": {"default_minutes": 5, "max_minutes": 10}
			},
			{
				"id": "request-dev",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["git.push.force"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/dev"]}],
				"grant_policy": {"default_minutes": 5, "max_minutes": 20}
			}
		]
	}`
	if _, err := Parse([]byte(disjointRefs)); err != nil {
		t.Fatalf("Parse(disjointRefs) error = %v", err)
	}

	disjointAttrs := `{
		"rules": [
			{
				"id": "request-fast-forward",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}],
				"attrs": {"ref_change": "fast_forward"},
				"grant_policy": {"default_minutes": 5, "max_minutes": 10}
			},
			{
				"id": "request-create",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}],
				"attrs": {"ref_change": "create"},
				"grant_policy": {"default_minutes": 5, "max_minutes": 20}
			}
		]
	}`
	if _, err := Parse([]byte(disjointAttrs)); err != nil {
		t.Fatalf("Parse(disjointAttrs) error = %v", err)
	}

	overlappingAttrs := strings.Replace(disjointAttrs, `"ref_change": "create"`, `"ref_change": ["create", "fast_forward"]`, 1)
	if _, err := Parse([]byte(overlappingAttrs)); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("Parse(overlappingAttrs) error = %v, want overlap", err)
	}
}

func TestInvalidOperationFamilyGlobAndTargetPath(t *testing.T) {
	_, err := Parse([]byte(`{
		"rules": [{
			"id": "bad-op",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["git.push.*"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}]
		}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "invalid operation-family glob") {
		t.Fatalf("bad op error = %v", err)
	}
	_, err = Parse([]byte(`{
		"rules": [{
			"id": "bad-path",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["repo.contents.read"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "paths": ["../secret"]}]
		}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "malformed glob") {
		t.Fatalf("bad path error = %v", err)
	}
	for _, badName := range []string{"repo[0-9]", `repo\1`} {
		nameJSON, err := json.Marshal(badName)
		if err != nil {
			t.Fatal(err)
		}
		body := strings.ReplaceAll(`{
			"rules": [{
				"id": "bad-name",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["repo.contents.read"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "BAD_NAME"}]
			}]
		}`, `"BAD_NAME"`, string(nameJSON))
		if _, err := Parse([]byte(body)); err == nil || !strings.Contains(err.Error(), "malformed glob") {
			t.Fatalf("bad name %q error = %v, want malformed glob", badName, err)
		}
	}
}

func TestRejectsOperationTargetKindMismatch(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "repo operation bucket target",
			body: `{"rules":[{
				"id":"repo-op-bucket-target",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.contents.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts"}]
			}]}`,
		},
		{
			name: "git operation bucket target",
			body: `{"rules":[{
				"id":"git-op-bucket-target",
				"effect":"allow",
				"clients":["agent"],
				"operations":["git.push.append"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts"}]
			}]}`,
		},
		{
			name: "bucket operation repo target",
			body: `{"rules":[{
				"id":"bucket-op-repo-target",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.write"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
			}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.body)); err == nil || !strings.Contains(err.Error(), "requires") {
				t.Fatalf("Parse() error = %v, want operation/target kind mismatch", err)
			}
		})
	}
}

func TestAttrs(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "small-fast-forward",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["git.push.append"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
			"attrs": {"ref_change": ["fast_forward"], "max_bytes": 1024}
		}]
	}`)
	req := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/main")
	req.Attrs = map[string]any{"ref_change": "fast_forward", "max_bytes": int64(100)}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("attr decision = %+v", got)
	}
	req.Attrs["max_bytes"] = int64(2048)
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("large attr decision = %+v", got)
	}
}

func TestCoreAttributeProjectionKeepsRegisteredAttributes(t *testing.T) {
	attrs := make(map[string]any, len(knownAttrs))
	for _, name := range KnownAttributeNames() {
		attrs[name] = "value"
	}
	for _, name := range []string{"max_bytes", "max_hosts", "num_hosts", "sleep_time_seconds", "warm_up"} {
		attrs[name] = int64(2)
	}
	projected := coreAttrsFromHF(attrs, coreViewNormal)
	for _, name := range KnownAttributeNames() {
		if len(projected[name]) != 1 || projected[name][0] == "" {
			t.Fatalf("registered attribute %q was dropped: %#v", name, projected)
		}
	}
	if got := canonicalCoreAttr("recursive", true); got != "invalid" {
		t.Fatalf("invalid recursive projection = %q", got)
	}
	if got := canonicalCoreAttr("unknown", "value"); got != "" {
		t.Fatalf("unknown attribute projection = %q", got)
	}
}

func TestSpecificSandboxAttributeDenyOverridesBroadAllow(t *testing.T) {
	pol := mustParse(t, `{"rules":[
		{"id":"deny-recursive","effect":"deny","clients":["agent"],"operations":["sandbox.file.delete"],"targets":[{"kind":"sandbox","owner":"acme","name":"worker"}],"attrs":{"recursive":"true"}},
		{"id":"allow-delete","effect":"allow","clients":["agent"],"operations":["sandbox.file.delete"],"targets":[{"kind":"sandbox","owner":"acme","name":"worker"}]}
	]}`)
	request := Request{Client: "agent", Operation: "sandbox.file.delete",
		Target: Target{Kind: "sandbox", Owner: "acme", Name: "worker"}, Attrs: map[string]any{"recursive": "true"}}
	decision := pol.Decide(request, nil, time.Now(), false)
	if decision.Effect != EffectDeny || !slices.Contains(decision.MatchedDenyRuleIDs, "deny-recursive") {
		t.Fatalf("recursive delete decision = %+v", decision)
	}
}

func TestRefLessSupportTrafficIgnoresRefSpecificPolicy(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [
			{
				"id": "deny-main",
				"effect": "deny",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/main"]}]
			},
			{
				"id": "deny-branch-create",
				"effect": "deny",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
				"attrs": {"ref_change": "create"}
			},
			{
				"id": "allow-small-fast-forward-dev",
				"effect": "allow",
				"clients": ["agent"],
				"operations": ["git.push.append"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "refs": ["refs/heads/dev"]}],
				"attrs": {"ref_change": "fast_forward", "max_bytes": 10}
			}
		]
	}`)
	req := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "")
	req.IgnoreRepoRefs = true
	req.Attrs = map[string]any{"max_bytes": int64(9)}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("ref-less support decision = %+v, want allow", got)
	}
	req.Attrs = map[string]any{"max_bytes": int64(11)}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("large ref-less support decision = %+v, want no match", got)
	}
}

func TestBucketRulesParseAndMatch(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "bucket-write",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["bucket.*"],
			"targets": [{
				"kind": "bucket",
				"owner": "acme",
				"name": "artifacts",
				"keys": ["runs/**"],
				"snapshot_prefix": "snapshots"
			}]
		}]
	}`)

	allowed := pol.Decide(bucketReq("agent", OpBucketObjectWrite, "acme", "artifacts", "runs/one/file"), nil, time.Now(), false)
	if allowed.Effect != EffectAllow {
		t.Fatalf("bucket write decision = %+v", allowed)
	}
	denied := pol.Decide(bucketReq("agent", OpBucketObjectRead, "acme", "artifacts", "other/file"), nil, time.Now(), false)
	if denied.Effect != EffectNoMatch {
		t.Fatalf("bucket read outside key decision = %+v", denied)
	}

	snapshotProtected := mustParse(t, `{
		"rules": [{
			"id": "bucket-write-with-snapshots",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["bucket.*"],
			"targets": [{
				"kind": "bucket",
				"owner": "acme",
				"name": "artifacts",
				"keys": ["**"],
				"snapshot_prefix": "snapshots"
			}]
		}]
	}`)
	for _, op := range []Operation{OpBucketObjectWrite, OpBucketObjectDel} {
		got := snapshotProtected.Decide(bucketReq("agent", op, "acme", "artifacts", "snapshots/object"), nil, time.Now(), false)
		if got.Effect != EffectNoMatch {
			t.Fatalf("%s under snapshot prefix = %+v, want no match", op, got)
		}
	}
	if got := snapshotProtected.Decide(bucketReq("agent", OpBucketObjectWrite, "acme", "artifacts", "snapshots-old/object"), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("write outside snapshot prefix = %+v, want allow", got)
	}
	if got := snapshotProtected.Decide(bucketReq("agent", OpBucketObjectRead, "acme", "artifacts", "snapshots/object"), nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("read under snapshot prefix = %+v, want allow", got)
	}
}

func TestInvalidBucketTargets(t *testing.T) {
	_, err := Parse([]byte(`{
		"rules": [{
			"id": "bad-bucket",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["bucket.object.read"],
			"targets": [{"kind": "bucket", "owner": "acme", "name": "artifacts", "snapshot_prefix": "../secret"}]
		}]
	}`))
	if err == nil || !strings.Contains(err.Error(), "snapshot_prefix") {
		t.Fatalf("bad bucket target error = %v, want snapshot_prefix", err)
	}

	pol := mustParse(t, `{"rules":[]}`)
	invalid := pol.Decide(Request{
		Client:    "agent",
		Operation: OpBucketObjectList,
		Target:    Target{Kind: KindBucket, Name: "artifacts"},
	}, nil, time.Now(), false)
	if invalid.Effect != EffectDeny || invalid.Reason != "invalid_target" {
		t.Fatalf("invalid bucket request decision = %+v", invalid)
	}
}

func TestRejectsWrongKindTargetFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "repo keys",
			body: `{"rules":[{
				"id":"repo-keys",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.contents.read"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","keys":["runs/**"]}]
			}]}`,
		},
		{
			name: "repo empty keys",
			body: `{"rules":[{
				"id":"repo-empty-keys",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.contents.read"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","keys":[]}]
			}]}`,
		},
		{
			name: "repo snapshot prefix",
			body: `{"rules":[{
				"id":"repo-snapshot",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.contents.read"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","snapshot_prefix":"snapshots"}]
			}]}`,
		},
		{
			name: "repo empty snapshot prefix",
			body: `{"rules":[{
				"id":"repo-empty-snapshot",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.contents.read"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","snapshot_prefix":""}]
			}]}`,
		},
		{
			name: "bucket empty type",
			body: `{"rules":[{
				"id":"bucket-empty-type",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","type":"","owner":"acme","name":"artifacts"}]
			}]}`,
		},
		{
			name: "bucket refs",
			body: `{"rules":[{
				"id":"bucket-refs",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","refs":["refs/heads/main"]}]
			}]}`,
		},
		{
			name: "bucket empty refs",
			body: `{"rules":[{
				"id":"bucket-empty-refs",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","refs":[]}]
			}]}`,
		},
		{
			name: "bucket paths",
			body: `{"rules":[{
				"id":"bucket-paths",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","paths":["README.md"]}]
			}]}`,
		},
		{
			name: "bucket empty paths",
			body: `{"rules":[{
				"id":"bucket-empty-paths",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","paths":[]}]
			}]}`,
		},
		{
			name: "bucket visibility",
			body: `{"rules":[{
				"id":"bucket-visibility",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","visibility":["private"]}]
			}]}`,
		},
		{
			name: "bucket empty visibility",
			body: `{"rules":[{
				"id":"bucket-empty-visibility",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","visibility":[]}]
			}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.body)); err == nil {
				t.Fatalf("Parse() succeeded, want wrong-kind target field error")
			}
		})
	}
}

func TestRejectsEmptyOptionalTargetLists(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "empty refs",
			body: `{"rules":[{
				"id":"empty-refs",
				"effect":"allow",
				"clients":["agent"],
				"operations":["git.push.append"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","refs":[]}]
			}]}`,
		},
		{
			name: "empty paths",
			body: `{"rules":[{
				"id":"empty-paths",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.contents.read"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","paths":[]}]
			}]}`,
		},
		{
			name: "empty visibility",
			body: `{"rules":[{
				"id":"empty-visibility",
				"effect":"allow",
				"clients":["agent"],
				"operations":["repo.metadata.read"],
				"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","visibility":[]}]
			}]}`,
		},
		{
			name: "empty keys",
			body: `{"rules":[{
				"id":"empty-keys",
				"effect":"allow",
				"clients":["agent"],
				"operations":["bucket.object.read"],
				"targets":[{"kind":"bucket","owner":"acme","name":"artifacts","keys":[]}]
			}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.body)); err == nil || !strings.Contains(err.Error(), "must not be empty") {
				t.Fatalf("Parse() error = %v, want empty optional target list error", err)
			}
		})
	}
}

func TestRepoVisibilityAndOperationFamilies(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "private-git",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["git.*"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo", "visibility": ["private"]}]
		}]
	}`)
	req := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/main")
	req.Target.Visibility = []string{"private"}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("private git force decision = %+v", got)
	}
	req.Target.Visibility = []string{"public"}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("public git force decision = %+v", got)
	}
}

func TestGrantPolicyValidation(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "execution-delete",
			"effect": "request",
			"clients": ["agent"],
			"operations": ["bucket.object.delete"],
			"targets": [{"kind": "bucket", "owner": "acme", "name": "artifacts"}],
			"grant_policy": {"mode": "execution", "default_max_uses": 5, "max_uses": 5}
		}]
	}`)
	decision := pol.Decide(bucketReq("agent", OpBucketObjectDel, "acme", "artifacts", "runs/one"), nil, time.Now(), true)
	if decision.Effect != EffectRequest || decision.GrantPolicy == nil || decision.GrantPolicy.MaxUses != 1 {
		t.Fatalf("execution grant policy decision = %+v", decision)
	}

	invalidPolicies := []string{
		`{"default_minutes": 0, "max_minutes": 5}`,
		`{"default_minutes": 5, "max_minutes": 4}`,
		`{"request_ttl_minutes": 0}`,
		`{"default_max_uses": 0}`,
		`{"default_max_uses": null, "max_uses": null}`,
		`{"default_max_uses": 2, "max_uses": 1}`,
	}
	for _, grantPolicy := range invalidPolicies {
		body := `{
			"rules": [{
				"id": "bad-grant",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["repo.contents.read"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
				"grant_policy": GRANT_POLICY
			}]
		}`
		if _, err := Parse([]byte(strings.Replace(body, "GRANT_POLICY", grantPolicy, 1))); err == nil {
			t.Fatalf("Parse() with grant_policy %s succeeded, want error", grantPolicy)
		}
	}
}

func TestGrantPolicyDefaultsAndGrantability(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "read-request",
			"effect": "request",
			"clients": ["agent"],
			"operations": ["repo.contents.read"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
			"grant_policy": {"default_max_uses": 5}
		}]
	}`)
	decision := pol.Decide(repoReq("agent", OpRepoContentsRead, "dataset", "acme", "repo", ""), nil, time.Now(), true)
	if decision.Effect != EffectRequest || decision.GrantPolicy == nil {
		t.Fatalf("Decide() = %+v, want request decision", decision)
	}
	if decision.GrantPolicy.DefaultMaxUses != 5 || decision.GrantPolicy.MaxUses != usebudget.MaxFiniteUses {
		t.Fatalf("grant policy = %+v, want operation maximum with finite default", decision.GrantPolicy)
	}

	for _, body := range []string{
		`{
			"rules": [{
				"id": "list-request",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["repo.list"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
				"grant_policy": {"mode": "window"}
			}]
		}`,
		`{
			"rules": [{
				"id": "mixed-request",
				"effect": "request",
				"clients": ["agent"],
				"operations": ["repo.list", "repo.contents.read"],
				"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
				"grant_policy": {}
			}]
		}`,
	} {
		if _, err := Parse([]byte(body)); err != nil {
			t.Fatalf("Parse() error = %v, want grantable window operations", err)
		}
	}
}

func TestNormalWritesMayUseWeekLongGrantBounds(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		name      string
		operation string
		target    string
	}{
		{name: "git append", operation: "git.push.append", target: `{"kind":"repo","type":"dataset","owner":"acme","name":"demo","refs":["refs/heads/main"]}`},
		{name: "repo commit", operation: "repo.commit.create", target: `{"kind":"repo","type":"dataset","owner":"acme","name":"demo","refs":["refs/heads/main"],"paths":["runs/**"]}`},
		{name: "bucket write", operation: "bucket.object.write", target: `{"kind":"bucket","owner":"acme","name":"artifacts","keys":["runs/**"]}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"rules":[{
				"id":"week","effect":"request","clients":["agent"],
				"operations":[%q],"targets":[%s],
				"grant_policy":{"mode":"window","default_minutes":5,"max_minutes":10080,"default_max_uses":1,"max_uses":null}
			}]}`, fixture.operation, fixture.target)
			if _, err := Parse([]byte(body)); err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
		})
	}

	body := `{"rules":[{
		"id":"delete-week","effect":"request","clients":["agent"],
		"operations":["bucket.object.delete"],
		"targets":[{"kind":"bucket","owner":"acme","name":"artifacts"}],
		"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":10080}
	}]}`
	if _, err := Parse([]byte(body)); err == nil || !strings.Contains(err.Error(), "max_minutes") {
		t.Fatalf("Parse() error = %v, want operation duration bound", err)
	}
}

func TestProtocolWindowAllowsExplicitUnlimitedUseBudget(t *testing.T) {
	t.Parallel()
	pol := mustParse(t, `{"rules":[{
		"id":"unlimited","effect":"request","clients":["bob"],
		"operations":["git.push.force"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"demo"}],
		"grant_policy":{"default_max_uses":3,"max_uses":null}
	}]}`)
	decision := pol.Decide(repoReq("bob", OpGitPushForce, "dataset", "acme", "demo", "refs/heads/main"), nil, time.Now(), true)
	if decision.GrantPolicy == nil || decision.GrantPolicy.DefaultMaxUses != 3 || !decision.GrantPolicy.MaxUses.IsUnlimited() {
		t.Fatalf("decision = %+v", decision)
	}
}

func TestNumberAttrsAcceptJSONNumberAndInt(t *testing.T) {
	pol := mustParse(t, `{
		"rules": [{
			"id": "small",
			"effect": "allow",
			"clients": ["agent"],
			"operations": ["git.push.append"],
			"targets": [{"kind": "repo", "type": "dataset", "owner": "acme", "name": "repo"}],
			"attrs": {"max_bytes": 10}
		}]
	}`)
	req := repoReq("agent", OpGitPushAppend, "dataset", "acme", "repo", "refs/heads/main")
	req.Attrs = map[string]any{"max_bytes": int(9)}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("int attr decision = %+v", got)
	}
	req.Attrs = map[string]any{"max_bytes": json.Number("10")}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectAllow {
		t.Fatalf("json.Number attr decision = %+v", got)
	}
	req.Attrs = map[string]any{"max_bytes": json.Number("not-a-number")}
	if got := pol.Decide(req, nil, time.Now(), false); got.Effect != EffectNoMatch {
		t.Fatalf("bad json.Number attr decision = %+v", got)
	}
}

func TestRejectsMatcherBoundaryWhitespace(t *testing.T) {
	for _, matcher := range []string{" docs/file", "docs/file "} {
		body := fmt.Sprintf(`{"rules":[{
			"id":"read-path",
			"effect":"allow",
			"clients":["agent"],
			"operations":["repo.contents.read"],
			"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo","paths":[%q]}]
		}]}`, matcher)
		if _, err := Parse([]byte(body)); err == nil || !strings.Contains(err.Error(), "malformed glob") {
			t.Fatalf("Parse(path %q) error = %v, want malformed glob", matcher, err)
		}
	}
}

func TestRepoCreateRequestPolicy(t *testing.T) {
	pol := mustParse(t, `{"rules":[{"id":"create","effect":"request","clients":["agent"],"operations":["repo.create"],"targets":[{"kind":"repo","type":"dataset","owner":"alice","name":"data"}],"attrs":{"private":"true"},"grant_policy":{"mode":"execution","default_minutes":5,"max_minutes":5,"request_ttl_minutes":5,"default_max_uses":1,"max_uses":1}}]}`)
	request := Request{Client: "agent", Operation: OpRepoCreate, Target: Target{Kind: KindRepo, Type: TypeDataset, Owner: "alice", Name: "data"}, Attrs: map[string]any{"private": "true"}}
	if blocked := pol.Decide(request, nil, time.Now(), false); blocked.Effect != EffectDeny || blocked.Reason != "approval_required" {
		t.Fatalf("runtime decision = %#v", blocked)
	}
	decision := pol.Decide(request, nil, time.Now(), true)
	if decision.Effect != EffectRequest {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestRepoCreateIsExcludedFromFamilyGlob(t *testing.T) {
	expanded, err := expandOperation("repo.*")
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range expanded {
		if operation == OpRepoCreate {
			t.Fatal("repo.* unexpectedly includes explicit-only repo.create")
		}
	}
}

func mustParse(t *testing.T, body string) Policy {
	t.Helper()
	pol, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return pol
}

func repoReq(client string, op Operation, repoType, owner, name, ref string) Request {
	target := Target{Kind: KindRepo, Type: RepoType(repoType), Owner: owner, Name: name}
	if ref != "" {
		target.Refs = []string{ref}
	}
	return Request{Client: client, Operation: op, Target: target}
}

func bucketReq(client string, op Operation, owner, name string, keys ...string) Request {
	return Request{
		Client:    client,
		Operation: op,
		Target:    Target{Kind: KindBucket, Owner: owner, Name: name, Keys: keys},
	}
}
