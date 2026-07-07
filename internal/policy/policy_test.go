package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseRejectsLegacyScopeFormat(t *testing.T) {
	_, err := Parse([]byte(`{"repos":[{"id":"acme/repo","type":"dataset"}]}`))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Parse() error = %v, want unknown field", err)
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
	if got := pol.DecideReceivePackDiscovery(req, time.Now()); got.Effect != EffectAllow {
		t.Fatalf("discovery with ref-scoped deny and allow = %+v, want allow", got)
	}

	broadDeny := mustParse(t, `{"rules":[{
		"id":"deny-repo",
		"effect":"deny",
		"clients":["agent"],
		"operations":["git.push.append"],
		"targets":[{"kind":"repo","type":"dataset","owner":"acme","name":"repo"}]
	}]}`)
	if got := broadDeny.DecideReceivePackDiscovery(req, time.Now()); got.Effect != EffectDeny {
		t.Fatalf("broad deny discovery = %+v, want deny", got)
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
	if _, err := Parse([]byte(differentPolicy)); err == nil || !strings.Contains(err.Error(), "overlaps") {
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
	if _, err := Parse([]byte(overlappingAttrs)); err == nil || !strings.Contains(err.Error(), "overlaps") {
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
	req := repoReq("agent", OpGitPushForce, "dataset", "acme", "repo", "refs/heads/main")
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
	if decision.GrantPolicy.DefaultMaxUses != 5 || decision.GrantPolicy.MaxUses != 5 {
		t.Fatalf("grant policy = %+v, want max_uses defaulted from default_max_uses", decision.GrantPolicy)
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
		if _, err := Parse([]byte(body)); err == nil || !strings.Contains(err.Error(), "not grantable") {
			t.Fatalf("Parse() error = %v, want not grantable", err)
		}
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

func TestSegmentGlobOverlapCases(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{a: "repo", b: "repo", want: true},
		{a: "repo", b: "other", want: false},
		{a: "repo-*", b: "repo-one", want: true},
		{a: "repo-one", b: "repo-*", want: true},
		{a: "repo-*", b: "data-*", want: true},
	}
	for _, tc := range cases {
		if got := segmentGlobsMayOverlap(tc.a, tc.b); got != tc.want {
			t.Fatalf("segmentGlobsMayOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestOptionalPrefixesMayOverlap(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{a: "", b: "runs/", want: true},
		{a: "runs/", b: "", want: true},
		{a: "runs/", b: "runs/2026/", want: true},
		{a: "runs/2026/", b: "runs/", want: true},
		{a: "runs/2025/", b: "runs/2026/", want: false},
	}
	for _, tc := range cases {
		if got := optionalPrefixesMayOverlap(tc.a, tc.b); got != tc.want {
			t.Fatalf("optionalPrefixesMayOverlap(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
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
