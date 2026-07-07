package policy

import (
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
