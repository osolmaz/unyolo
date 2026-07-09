package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseValidatesRegistryVocabulary(t *testing.T) {
	_, err := Parse([]byte(`{"rules":[{
		"id":"bad-op",
		"effect":"allow",
		"clients":["bob"],
		"operations":["repo.delete"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}]
	}]}`), testRegistry())
	if err == nil || !strings.Contains(err.Error(), "unknown operation") {
		t.Fatalf("Parse() error = %v, want unknown operation", err)
	}

	_, err = Parse([]byte(`{"rules":[{
		"id":"bad-target",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.fetch"],
		"targets":[{"kind":"bucket","name":"artifacts"}]
	}]}`), testRegistry())
	if err == nil || !strings.Contains(err.Error(), "unknown target kind") {
		t.Fatalf("Parse() error = %v, want unknown target kind", err)
	}
}

func TestDecisionOrder(t *testing.T) {
	policy := mustParse(t, `{"rules":[
		{
			"id":"allow-feature",
			"effect":"allow",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}],
			"attrs":{"ref":["refs/heads/bob/*"]}
		},
		{
			"id":"deny-main",
			"effect":"deny",
			"clients":["*"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}],
			"attrs":{"ref":["refs/heads/main"]}
		},
		{
			"id":"request-main",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}],
			"attrs":{"ref":["refs/heads/main"]},
			"grant_policy":{"default_minutes":5,"max_minutes":10}
		}
	]}`)
	feature := policy.Decide(repoReq("bob", "git.push.fast_forward", "demo", "refs/heads/bob/change"), DecisionOptions{})
	if !feature.Allowed || feature.Reason != "policy_allowed" {
		t.Fatalf("feature decision = %+v", feature)
	}

	activeGrant := Grant{
		ID:        "grant-1",
		Client:    "bob",
		Operation: "git.push.fast_forward",
		Target:    Target{Kind: "repo", Fields: map[string]string{"owner": "osolmaz", "name": "demo"}},
		Attrs:     map[string]string{"ref": "refs/heads/main"},
		ExpiresAt: time.Now().Add(time.Minute),
		UsesLeft:  1,
	}
	main := policy.Decide(repoReq("bob", "git.push.fast_forward", "demo", "refs/heads/main"), DecisionOptions{ActiveGrants: []Grant{activeGrant}})
	if main.Effect != EffectDeny || main.Reason != "policy_denied" {
		t.Fatalf("deny should beat active grant, got %+v", main)
	}

	request := policy.Decide(repoReq("bob", "git.push.fast_forward", "demo", "refs/heads/main"), DecisionOptions{ForGrantRequest: true})
	if request.Effect != EffectDeny {
		t.Fatalf("deny should beat request, got %+v", request)
	}
}

func TestRequestRuleAndGrantOverlay(t *testing.T) {
	policy := mustParse(t, `{"rules":[{
		"id":"request-shell",
		"effect":"request",
		"clients":["bob"],
		"operations":["session.shell"],
		"targets":[{"kind":"user","name":"deploy"}],
		"grant_policy":{"default_minutes":5,"max_minutes":10,"default_max_uses":1,"max_uses":1}
	}]}`)
	req := Request{Client: "bob", Operation: "session.shell", Target: Target{Kind: "user", Fields: map[string]string{"name": "deploy"}}}
	execDecision := policy.Decide(req, DecisionOptions{})
	if execDecision.Effect != EffectDeny || execDecision.Reason != "approval_required" {
		t.Fatalf("execution decision = %+v", execDecision)
	}
	requestDecision := policy.Decide(req, DecisionOptions{ForGrantRequest: true})
	if requestDecision.Effect != EffectRequest || requestDecision.GrantPolicy == nil {
		t.Fatalf("grant request decision = %+v", requestDecision)
	}
	grantDecision := policy.Decide(req, DecisionOptions{ActiveGrants: []Grant{{
		ID:        "grant-shell",
		Client:    "bob",
		Operation: "session.shell",
		Target:    Target{Kind: "user", Fields: map[string]string{"name": "deploy"}},
		ExpiresAt: time.Now().Add(time.Minute),
		UsesLeft:  1,
	}}})
	if !grantDecision.Allowed || grantDecision.GrantID != "grant-shell" {
		t.Fatalf("grant decision = %+v", grantDecision)
	}
}

func TestGrantOverlayRequiresRemainingUseBudget(t *testing.T) {
	policy := requestShellPolicy(t)
	req := Request{Client: "bob", Operation: "session.shell", Target: Target{Kind: "user", Fields: map[string]string{"name": "deploy"}}}
	exhaustedDecision := policy.Decide(req, DecisionOptions{ActiveGrants: []Grant{{
		ID:        "grant-shell",
		Client:    "bob",
		Operation: "session.shell",
		Target:    Target{Kind: "user", Fields: map[string]string{"name": "deploy"}},
		ExpiresAt: time.Now().Add(time.Minute),
		UsesLeft:  0,
	}}})
	if exhaustedDecision.Allowed || exhaustedDecision.Reason == "grant_allowed" {
		t.Fatalf("exhausted grant decision = %+v, want denied", exhaustedDecision)
	}
}

func TestGrantOverlayRequiresExpiry(t *testing.T) {
	policy := requestShellPolicy(t)
	req := Request{Client: "bob", Operation: "session.shell", Target: Target{Kind: "user", Fields: map[string]string{"name": "deploy"}}}
	decision := policy.Decide(req, DecisionOptions{ActiveGrants: []Grant{{
		ID:        "grant-shell",
		Client:    "bob",
		Operation: "session.shell",
		Target:    Target{Kind: "user", Fields: map[string]string{"name": "deploy"}},
		UsesLeft:  1,
	}}})
	if decision.Allowed || decision.Reason == "grant_allowed" {
		t.Fatalf("missing expiry grant decision = %+v, want denied", decision)
	}
}

func TestGrantOverlayRequiresExactAttrs(t *testing.T) {
	policy := requestShellPolicy(t)
	extraAttrDecision := policy.Decide(Request{
		Client:    "bob",
		Operation: "session.shell",
		Target:    Target{Kind: "user", Fields: map[string]string{"name": "deploy"}},
		Attrs:     map[string]string{"tty": "true"},
	}, DecisionOptions{ActiveGrants: []Grant{{
		ID:        "grant-shell",
		Client:    "bob",
		Operation: "session.shell",
		Target:    Target{Kind: "user", Fields: map[string]string{"name": "deploy"}},
		ExpiresAt: time.Now().Add(time.Minute),
		UsesLeft:  1,
	}}})
	if extraAttrDecision.Allowed || extraAttrDecision.Reason == "grant_allowed" {
		t.Fatalf("extra attr grant decision = %+v, want denied", extraAttrDecision)
	}
}

func TestProviderDeclaredMatcherSemantics(t *testing.T) {
	registry := Registry{
		Operations: map[string]OperationSpec{
			"bucket.object.write": {
				TargetKinds: []string{"bucket"},
				Attrs:       []string{"max_bytes"},
			},
		},
		Targets: map[string]TargetSpec{
			"bucket": {Fields: map[string]FieldSpec{
				"owner": {Required: true},
				"name":  {Required: true},
				"key":   {Required: true, Match: MatchPathGlob},
			}},
		},
		Attrs: map[string]AttrSpec{
			"max_bytes": {Match: MatchIntegerMaximum},
		},
	}
	policy := mustParseWithRegistry(t, `{"rules":[{
		"id":"bounded-write",
		"effect":"allow",
		"clients":["bob"],
		"operations":["bucket.object.write"],
		"targets":[{"kind":"bucket","owner":"osolmaz","name":"artifacts","key":"runs/**/*.json"}],
		"attrs":{"max_bytes":"10"}
	}]}`, registry)
	request := Request{
		Client:    "bob",
		Operation: "bucket.object.write",
		Target: Target{Kind: "bucket", Fields: map[string]string{
			"owner": "osolmaz",
			"name":  "artifacts",
			"key":   "runs/2026/day/out.json",
		}},
		Attrs: map[string]string{"max_bytes": "9"},
	}
	if decision := policy.Decide(request, DecisionOptions{}); !decision.Allowed {
		t.Fatalf("bounded path decision = %+v, want allowed", decision)
	}
	request.Target.Fields["key"] = "runs/out.json"
	if decision := policy.Decide(request, DecisionOptions{}); !decision.Allowed {
		t.Fatalf("zero-segment ** decision = %+v, want allowed", decision)
	}
	request.Attrs["max_bytes"] = "11"
	if decision := policy.Decide(request, DecisionOptions{}); decision.Allowed {
		t.Fatalf("over-limit decision = %+v, want refused", decision)
	}
}

func TestProviderMatcherValidation(t *testing.T) {
	registry := Registry{
		Operations: map[string]OperationSpec{
			"write": {TargetKinds: []string{"object"}, Attrs: []string{"max_bytes"}},
		},
		Targets: map[string]TargetSpec{
			"object": {Fields: map[string]FieldSpec{"key": {Required: true, Match: MatchPathGlob}}},
		},
		Attrs: map[string]AttrSpec{"max_bytes": {Match: MatchIntegerMaximum}},
	}
	cases := []struct {
		name   string
		target string
		limit  string
	}{
		{name: "embedded double star", target: "runs/a**/out", limit: "10"},
		{name: "bad path glob", target: "runs/[a/out", limit: "10"},
		{name: "negative maximum", target: "runs/**/out", limit: "-1"},
		{name: "non-integer maximum", target: "runs/**/out", limit: "ten"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"rules":[{"id":"bad","effect":"allow","clients":["bob"],"operations":["write"],"targets":[{"kind":"object","key":"` + tc.target + `"}],"attrs":{"max_bytes":"` + tc.limit + `"}}]}`
			if _, err := Parse([]byte(body), registry); err == nil {
				t.Fatal("Parse() error = nil, want invalid provider matcher value")
			}
		})
	}
}

func TestPathGlobValidationBounds(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
	}{
		{name: "oversized pattern", pattern: strings.Repeat("a", maxPathPatternBytes+1)},
		{name: "too many segments", pattern: strings.Repeat("a/", maxPathSegments) + "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePathGlob(tc.pattern); err == nil {
				t.Fatal("validatePathGlob() error = nil, want size limit error")
			}
		})
	}
}

func TestPathMatcherEdgeCases(t *testing.T) {
	cases := []struct {
		patterns []string
		values   []string
		want     bool
	}{
		{patterns: nil, values: nil, want: true},
		{patterns: []string{"**"}, values: nil, want: true},
		{patterns: []string{"**"}, values: []string{"a", "b"}, want: true},
		{patterns: []string{"a"}, values: nil, want: false},
		{patterns: []string{"a"}, values: []string{"b"}, want: false},
		{patterns: []string{"a"}, values: []string{"a"}, want: true},
	}
	for _, tc := range cases {
		if got := pathSegmentsMatch(tc.patterns, tc.values); got != tc.want {
			t.Fatalf("pathSegmentsMatch(%v, %v) = %t, want %t", tc.patterns, tc.values, got, tc.want)
		}
	}
	if pathPatternsMatch([]string{"a"}, "") {
		t.Fatal("pathPatternsMatch() matched an empty value")
	}
	if integerMaximumMatches([]string{"bad"}, "1") || integerMaximumMatches([]string{"1"}, "bad") || integerMaximumMatches([]string{"1"}, "-1") {
		t.Fatal("integerMaximumMatches() accepted malformed input")
	}
}

func TestPathMatcherBoundsRequestValues(t *testing.T) {
	value := strings.Repeat("a/", maxPathSegments) + "a"
	if pathPatternsMatch([]string{"**"}, value) {
		t.Fatal("pathPatternsMatch() accepted too many request path segments")
	}
	value = strings.Repeat("a", maxPathValueBytes+1)
	if pathPatternsMatch([]string{"*"}, value) {
		t.Fatal("pathPatternsMatch() accepted an oversized request path")
	}
}

func TestPathMatcherOverlapIsConservative(t *testing.T) {
	cases := []struct {
		left  string
		right string
		want  bool
	}{
		{left: "a", right: "a", want: true},
		{left: "a", right: "b", want: false},
		{left: "a", right: "*", want: true},
		{left: "*", right: "a", want: true},
		{left: "a/*", right: "b/*", want: true},
		{left: `a\b`, right: "ab", want: true},
	}
	for _, tc := range cases {
		if got := pathValuesMayOverlap(tc.left, tc.right); got != tc.want {
			t.Fatalf("pathValuesMayOverlap(%q, %q) = %t, want %t", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestEscapedPathPatternsCannotEvadeAmbiguityValidation(t *testing.T) {
	registry := Registry{
		Operations: map[string]OperationSpec{"read": {TargetKinds: []string{"object"}, Grantable: true}},
		Targets: map[string]TargetSpec{
			"object": {Fields: map[string]FieldSpec{"key": {Required: true, Match: MatchPathGlob}}},
		},
	}
	_, err := Parse([]byte(`{"rules":[
		{"id":"escaped","effect":"request","clients":["bob"],"operations":["read"],"targets":[{"kind":"object","key":"a\\b"}],"grant_policy":{"default_minutes":60,"max_minutes":60}},
		{"id":"literal","effect":"request","clients":["bob"],"operations":["read"],"targets":[{"kind":"object","key":"ab"}],"grant_policy":{"default_minutes":5,"max_minutes":5}}
	]}`), registry)
	if err == nil || !strings.Contains(err.Error(), "overlap with different grant policies") {
		t.Fatalf("Parse() error = %v, want escaped-pattern overlap", err)
	}
}

func TestProviderDeclaredExecutionGrantMode(t *testing.T) {
	registry := Registry{
		Operations: map[string]OperationSpec{
			"bucket.object.delete": {
				TargetKinds: []string{"bucket"},
				Grantable:   true,
				GrantMode:   GrantModeExecution,
			},
		},
		Targets: map[string]TargetSpec{
			"bucket": {Fields: map[string]FieldSpec{"name": {Required: true}}},
		},
	}
	policy := mustParseWithRegistry(t, `{"rules":[{
		"id":"request-delete",
		"effect":"request",
		"clients":["bob"],
		"operations":["bucket.object.delete"],
		"targets":[{"kind":"bucket","name":"artifacts"}],
		"grant_policy":{"default_minutes":5,"max_minutes":5}
	}]}`, registry)
	decision := policy.Decide(Request{
		Client:    "bob",
		Operation: "bucket.object.delete",
		Target:    Target{Kind: "bucket", Fields: map[string]string{"name": "artifacts"}},
	}, DecisionOptions{ForGrantRequest: true})
	if decision.GrantPolicy == nil || decision.GrantPolicy.Mode != string(GrantModeExecution) || decision.GrantPolicy.MaxUses != 1 {
		t.Fatalf("execution grant policy = %+v", decision.GrantPolicy)
	}
}

func TestProviderDeclaredGrantModeValidation(t *testing.T) {
	registry := Registry{
		Operations: map[string]OperationSpec{
			"window":    {TargetKinds: []string{"object"}, Grantable: true},
			"execution": {TargetKinds: []string{"object"}, Grantable: true, GrantMode: GrantModeExecution},
		},
		Targets: map[string]TargetSpec{"object": {Fields: map[string]FieldSpec{"name": {Required: true}}}},
	}
	cases := []string{
		`{"rules":[{"id":"bad","effect":"request","clients":["bob"],"operations":["execution"],"targets":[{"kind":"object","name":"one"}],"grant_policy":{"mode":"window"}}]}`,
		`{"rules":[{"id":"bad","effect":"request","clients":["bob"],"operations":["execution"],"targets":[{"kind":"object","name":"one"}],"grant_policy":{"default_max_uses":2,"max_uses":2}}]}`,
		`{"rules":[{"id":"bad","effect":"request","clients":["bob"],"operations":["window","execution"],"targets":[{"kind":"object","name":"one"}],"grant_policy":{}}]}`,
	}
	for _, body := range cases {
		if _, err := Parse([]byte(body), registry); err == nil {
			t.Fatal("Parse() error = nil, want incompatible grant mode")
		}
	}
}

func TestGrantOverlayDistinguishesEmptyAttrKeys(t *testing.T) {
	policy := mustParse(t, `{"rules":[{
		"id":"request-push",
		"effect":"request",
		"clients":["bob"],
		"operations":["git.push.fast_forward"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
		"grant_policy":{"default_minutes":5,"max_minutes":10}
	}]}`)
	decision := policy.Decide(Request{
		Client:    "bob",
		Operation: "git.push.fast_forward",
		Target:    Target{Kind: "repo", Fields: map[string]string{"owner": "osolmaz", "name": "demo"}},
		Attrs:     map[string]string{"refs": ""},
	}, DecisionOptions{ActiveGrants: []Grant{{
		ID:        "grant-push",
		Client:    "bob",
		Operation: "git.push.fast_forward",
		Target:    Target{Kind: "repo", Fields: map[string]string{"owner": "osolmaz", "name": "demo"}},
		Attrs:     map[string]string{"ref": ""},
		ExpiresAt: time.Now().Add(time.Minute),
		UsesLeft:  1,
	}}})
	if decision.Allowed || decision.Reason == "grant_allowed" {
		t.Fatalf("different empty attr keys matched grant: %+v", decision)
	}
}

func TestGitHubPRWorkflowAndDirectMainException(t *testing.T) {
	policy := mustParse(t, `{"rules":[
		{
			"id":"bob-fetch-workflow",
			"effect":"allow",
			"clients":["bob"],
			"operations":["git.fetch"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}]
		},
		{
			"id":"bob-branch-workflow",
			"effect":"allow",
			"clients":["bob"],
			"operations":["git.push.branch_create","git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}],
			"attrs":{"ref":["refs/heads/bob/*"]}
		},
		{
			"id":"bob-pr-workflow",
			"effect":"allow",
			"clients":["bob"],
			"operations":["pr.create"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}],
			"attrs":{"base_ref":["refs/heads/main"],"head_ref":["refs/heads/bob/*"]}
		},
		{
			"id":"direct-main-special",
			"effect":"allow",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"direct-main"}],
			"attrs":{"ref":["refs/heads/main"]}
		}
	]}`)
	if got := policy.Decide(repoReq("bob", "pr.create", "demo", ""), DecisionOptions{}); !got.Allowed {
		t.Fatalf("PR decision = %+v, want allowed", got)
	}
	if got := policy.Decide(repoReq("bob", "git.push.fast_forward", "demo", "refs/heads/main"), DecisionOptions{}); got.Allowed {
		t.Fatalf("default branch decision = %+v, want refused", got)
	}
	if got := policy.Decide(repoReq("bob", "git.push.fast_forward", "direct-main", "refs/heads/main"), DecisionOptions{}); !got.Allowed {
		t.Fatalf("direct main decision = %+v, want allowed", got)
	}
}

func TestParseNormalizesTargetPatterns(t *testing.T) {
	policy := mustParse(t, `{"rules":[{
		"id":"allow-trimmed-target",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","owner":" osolmaz ","name":" demo "}]
	}]}`)
	decision := policy.Decide(repoReq("bob", "git.fetch", "demo", ""), DecisionOptions{})
	if !decision.Allowed {
		t.Fatalf("trimmed target decision = %+v, want allowed", decision)
	}
}

func TestPolicyDoesNotExposeMutableInternals(t *testing.T) {
	registry := testRegistry()
	policy := mustParseWithRegistry(t, `{"rules":[{
		"id":"allow-fetch",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}]
	}]}`, registry)
	registry.Operations["git.fetch"] = OperationSpec{TargetKinds: []string{"user"}}
	if got := policy.Decide(repoReq("bob", "git.fetch", "demo", ""), DecisionOptions{}); !got.Allowed {
		t.Fatalf("decision after registry mutation = %+v, want allowed", got)
	}
	rules := policy.Rules()
	rules[0].Targets[0].Fields["name"][0] = "other"
	if got := policy.Decide(repoReq("bob", "git.fetch", "demo", ""), DecisionOptions{}); !got.Allowed {
		t.Fatalf("decision after Rules mutation = %+v, want allowed", got)
	}
}

func TestAttrNamesAreMatchedLiterally(t *testing.T) {
	policy := mustParse(t, `{"rules":[{
		"id":"plural-ref-rule",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.push.fast_forward"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
		"attrs":{"refs":["refs/heads/main"]}
	}]}`)
	decision := policy.Decide(repoReq("bob", "git.push.fast_forward", "demo", "refs/heads/main"), DecisionOptions{})
	if decision.Allowed {
		t.Fatalf("plural attr rule matched singular request attr: %+v", decision)
	}
}

func TestRejectsGeneratedGrantWildcardByConstruction(t *testing.T) {
	policy := mustParse(t, `{"rules":[{
		"id":"allow-read",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}]
	}]}`)
	req := repoReq("bob", "git.fetch", "demo", "")
	decision := policy.Decide(req, DecisionOptions{ActiveGrants: []Grant{{
		ID:        "bad-grant",
		Client:    "*",
		Operation: "git.fetch",
		Target:    Target{Kind: "repo", Fields: map[string]string{"owner": "osolmaz", "name": "demo"}},
		ExpiresAt: time.Now().Add(time.Minute),
		UsesLeft:  1,
	}}})
	if decision.Reason == "grant_allowed" {
		t.Fatalf("wildcard grant matched: %+v", decision)
	}
}

func TestParseRejectsInvalidGrantPolicies(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "allow with grant policy", body: `"effect":"allow","grant_policy":{"default_minutes":5}`},
		{name: "request without grant policy", body: `"effect":"request"`},
		{name: "bad mode", body: `"effect":"request","grant_policy":{"mode":"execution"}`},
		{name: "bad minutes", body: `"effect":"request","grant_policy":{"default_minutes":20,"max_minutes":10}`},
		{name: "too many minutes", body: `"effect":"request","grant_policy":{"default_minutes":60,"max_minutes":61}`},
		{name: "bad request ttl", body: `"effect":"request","grant_policy":{"request_ttl_minutes":-1}`},
		{name: "too much request ttl", body: `"effect":"request","grant_policy":{"request_ttl_minutes":61}`},
		{name: "bad uses", body: `"effect":"request","grant_policy":{"default_max_uses":2,"max_uses":1}`},
		{name: "too many uses", body: `"effect":"request","grant_policy":{"default_max_uses":25,"max_uses":26}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(`{"rules":[{
				"id":"grant-policy",
				`+tc.body+`,
				"clients":["bob"],
				"operations":["session.shell"],
				"targets":[{"kind":"user","name":"deploy"}]
			}]}`), testRegistry())
			if err == nil {
				t.Fatal("Parse() error = nil, want invalid grant policy")
			}
		})
	}
}

func TestParseRejectsAmbiguousRequestGrantPolicies(t *testing.T) {
	_, err := Parse([]byte(`{"rules":[
		{
			"id":"broad",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"*"}],
			"attrs":{"refs":["refs/heads/*"]},
			"grant_policy":{"default_minutes":60,"max_minutes":60}
		},
		{
			"id":"main",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
			"attrs":{"refs":["refs/heads/main"]},
			"grant_policy":{"default_minutes":5,"max_minutes":5}
		}
	]}`), testRegistry())
	if err == nil || !strings.Contains(err.Error(), "overlap with different grant policies") {
		t.Fatalf("Parse(ambiguous request policies) error = %v, want overlap error", err)
	}
}

func TestParseAllowsDisjointRequestGrantPolicies(t *testing.T) {
	_, err := Parse([]byte(`{"rules":[
		{
			"id":"main",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
			"attrs":{"refs":["refs/heads/main"]},
			"grant_policy":{"default_minutes":5,"max_minutes":5}
		},
		{
			"id":"feature",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
			"attrs":{"refs":["refs/heads/feature"]},
			"grant_policy":{"default_minutes":60,"max_minutes":60}
		}
	]}`), testRegistry())
	if err != nil {
		t.Fatalf("Parse(disjoint request policies) error = %v", err)
	}
}

func TestParseAllowsDisjointGlobRequestGrantPolicies(t *testing.T) {
	_, err := Parse([]byte(`{"rules":[
		{
			"id":"feature",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
			"attrs":{"refs":["refs/heads/feature/*"]},
			"grant_policy":{"default_minutes":5,"max_minutes":5}
		},
		{
			"id":"release",
			"effect":"request",
			"clients":["bob"],
			"operations":["git.push.fast_forward"],
			"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],
			"attrs":{"refs":["refs/heads/release/*"]},
			"grant_policy":{"default_minutes":60,"max_minutes":60}
		}
	]}`), testRegistry())
	if err != nil {
		t.Fatalf("Parse(disjoint glob request policies) error = %v", err)
	}
}

func TestParseRejectsInvalidRulesAndRequests(t *testing.T) {
	_, err := Parse([]byte(`{"rules":[]}`), testRegistry())
	if err == nil || !strings.Contains(err.Error(), "rules must not be empty") {
		t.Fatalf("Parse(empty rules) error = %v, want empty rules error", err)
	}
	_, err = Parse([]byte(`{"rules":[{
		"id":"",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}]
	}]}`), testRegistry())
	if err == nil || !strings.Contains(err.Error(), "id is required") {
		t.Fatalf("Parse(empty id) error = %v", err)
	}
	pol := mustParse(t, `{"rules":[{
		"id":"allow-fetch",
		"effect":"allow",
		"clients":["bob"],
		"operations":["git.fetch"],
		"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}]
	}]}`)
	decision := pol.Decide(Request{Client: "bob", Operation: "git.fetch", Target: Target{Kind: "repo", Fields: map[string]string{"owner": "osolmaz"}}}, DecisionOptions{})
	if decision.Effect != EffectNoMatch || !strings.Contains(decision.Reason, "requires field") {
		t.Fatalf("missing target field decision = %+v", decision)
	}
}

func TestParseRejectsTargetAndAttrMismatches(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "unsupported target field",
			body: `"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"osolmaz","name":"demo","extra":"x"}]`,
			want: "does not support field",
		},
		{
			name: "missing required target field",
			body: `"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"osolmaz"}]`,
			want: "requires field",
		},
		{
			name: "unknown attr",
			body: `"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],"attrs":{"unknown":"x"}`,
			want: "unknown attr",
		},
		{
			name: "attr not supported by operations",
			body: `"operations":["git.fetch"],"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],"attrs":{"refs":"refs/heads/main"}`,
			want: "does not support attr",
		},
		{
			name: "attr must constrain every listed operation",
			body: `"operations":["git.fetch","git.push.fast_forward"],"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],"attrs":{"refs":"refs/heads/main"}`,
			want: "does not support attr",
		},
		{
			name: "non grantable request",
			body: `"effect":"request","operations":["git.fetch"],"targets":[{"kind":"repo","owner":"osolmaz","name":"demo"}],"grant_policy":{"default_minutes":5}`,
			want: "not grantable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			effect := `"effect":"allow",`
			if strings.Contains(tc.body, `"effect":`) {
				effect = ""
			}
			_, err := Parse([]byte(`{"rules":[{
				"id":"bad",
				`+effect+`
				"clients":["bob"],
				`+tc.body+`
			}]}`), testRegistry())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRegistryValidationErrors(t *testing.T) {
	registries := []Registry{
		{},
		{Operations: map[string]OperationSpec{"": {TargetKinds: []string{"repo"}}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {}}}}},
		{Operations: map[string]OperationSpec{"op": {}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {}}}}},
		{Operations: map[string]OperationSpec{"op": {TargetKinds: []string{"missing"}}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {}}}}},
		{Operations: map[string]OperationSpec{"op": {TargetKinds: []string{"repo"}, Attrs: []string{"missing"}}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {}}}}},
		{Operations: map[string]OperationSpec{"op": {TargetKinds: []string{"repo"}}}, Targets: map[string]TargetSpec{"": {Fields: map[string]FieldSpec{"name": {}}}}},
		{Operations: map[string]OperationSpec{"op": {TargetKinds: []string{"repo"}, GrantMode: GrantModeExecution}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {}}}}},
		{Operations: map[string]OperationSpec{"op": {TargetKinds: []string{"repo"}}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {Match: MatchMode("bad")}}}}},
		{Operations: map[string]OperationSpec{"op": {TargetKinds: []string{"repo"}}}, Targets: map[string]TargetSpec{"repo": {Fields: map[string]FieldSpec{"name": {}}}}, Attrs: map[string]AttrSpec{"bad": {Match: MatchMode("bad")}}},
	}
	for index, registry := range registries {
		if _, err := Parse([]byte(`{"rules":[]}`), registry); err == nil {
			t.Fatalf("registry %d Parse() error = nil, want validation error", index)
		}
	}
}

func TestFieldlessTargetKind(t *testing.T) {
	registry := Registry{
		Operations: map[string]OperationSpec{"installation.repos.list": {TargetKinds: []string{"installation"}}},
		Targets:    map[string]TargetSpec{"installation": {}},
		Attrs:      map[string]AttrSpec{},
	}
	policy := mustParseWithRegistry(t, `{"rules":[{
		"id":"list-installation",
		"effect":"allow",
		"clients":["bob"],
		"operations":["installation.repos.list"],
		"targets":[{"kind":"installation"}]
	}]}`, registry)
	decision := policy.Decide(Request{Client: "bob", Operation: "installation.repos.list", Target: Target{Kind: "installation"}}, DecisionOptions{})
	if !decision.Allowed {
		t.Fatalf("fieldless target decision = %+v, want allowed", decision)
	}
}

func mustParse(t *testing.T, data string) *Policy {
	t.Helper()
	return mustParseWithRegistry(t, data, testRegistry())
}

func mustParseWithRegistry(t *testing.T, data string, registry Registry) *Policy {
	t.Helper()
	policy, err := Parse([]byte(data), registry)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	return policy
}

func requestShellPolicy(t *testing.T) *Policy {
	t.Helper()
	return mustParse(t, `{"rules":[{
		"id":"request-shell",
		"effect":"request",
		"clients":["bob"],
		"operations":["session.shell"],
		"targets":[{"kind":"user","name":"deploy"}],
		"grant_policy":{"default_minutes":5,"max_minutes":10,"default_max_uses":1,"max_uses":1}
	}]}`)
}

func repoReq(client string, operation string, name string, ref string) Request {
	attrs := map[string]string{}
	if ref != "" {
		attrs["ref"] = ref
	}
	if operation == "pr.create" {
		attrs["base_ref"] = "refs/heads/main"
		attrs["head_ref"] = "refs/heads/bob/change"
	}
	return Request{
		Client:    client,
		Operation: operation,
		Target: Target{
			Kind:   "repo",
			Fields: map[string]string{"owner": "osolmaz", "name": name},
		},
		Attrs: attrs,
	}
}

func testRegistry() Registry {
	return Registry{
		Operations: map[string]OperationSpec{
			"git.fetch":              {TargetKinds: []string{"repo"}},
			"git.push.branch_create": {TargetKinds: []string{"repo"}, Attrs: []string{"ref", "refs"}, Grantable: true},
			"git.push.fast_forward":  {TargetKinds: []string{"repo"}, Attrs: []string{"ref", "refs"}, Grantable: true},
			"pr.create":              {TargetKinds: []string{"repo"}, Attrs: []string{"base_ref", "base_refs", "head_ref", "head_refs"}, Grantable: true},
			"session.shell":          {TargetKinds: []string{"user"}, Grantable: true},
		},
		Targets: map[string]TargetSpec{
			"repo": {Fields: map[string]FieldSpec{"owner": {Required: true}, "name": {Required: true}}},
			"user": {Fields: map[string]FieldSpec{"name": {Required: true}}},
		},
		Attrs: map[string]AttrSpec{
			"ref":       {},
			"refs":      {},
			"base_ref":  {},
			"base_refs": {},
			"head_ref":  {},
			"head_refs": {},
		},
	}
}
