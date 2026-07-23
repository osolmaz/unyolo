package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCatalogOperationsAndTargetKindsAreClosed(t *testing.T) {
	t.Parallel()
	registered := Operations()
	if len(registered) < 200 || !slices.IsSorted(registered) {
		t.Fatalf("Operations() returned %d unsorted operations", len(registered))
	}
	if !IsOperation("repo.delete") || IsOperation("repo.destroy-everything") {
		t.Fatal("operation registry membership mismatch")
	}

	var genericKind TargetKind
	for _, operation := range registered {
		kind := operationTargetKind(operation)
		if kind != KindRepo && kind != KindBucket && kind != KindInference {
			genericKind = kind
			break
		}
	}
	if genericKind == "" || !knownTargetKind(genericKind) {
		t.Fatal("catalog did not expose a generic administrative target kind")
	}
	if knownTargetKind("unknown") {
		t.Fatal("unknown target kind was accepted")
	}

	for _, target := range []TargetMatcher{
		{Kind: genericKind, Owner: "acme", Name: "resource"},
		{Kind: KindInference, Owner: "acme", Name: "model"},
	} {
		candidate := target
		if err := validateTarget("target", &candidate); err != nil {
			t.Fatalf("validateTarget(%+v) = %v", target, err)
		}
	}
	genericWithRepoField := TargetMatcher{Kind: genericKind, Owner: "acme", Name: "resource", Type: TypeModel, typeSet: true}
	if err := validateTarget("target", &genericWithRepoField); err == nil {
		t.Fatal("generic target accepted repo-only type")
	}
	inferenceWithPaths := TargetMatcher{Kind: KindInference, Owner: "acme", Name: "model", Paths: []string{"*"}, pathsSet: true}
	if err := validateTarget("target", &inferenceWithPaths); err == nil {
		t.Fatal("inference target accepted paths")
	}
	unknown := TargetMatcher{Kind: "unknown", Owner: "acme", Name: "resource"}
	if err := validateTarget("target", &unknown); err == nil {
		t.Fatal("unknown target kind was accepted")
	}

	for _, target := range []Target{
		{Kind: genericKind, Owner: "acme", Name: "resource"},
		{Kind: KindInference, Owner: "acme", Name: "model"},
	} {
		if err := validateRequestTarget(target); err != nil {
			t.Fatalf("validateRequestTarget(%+v) = %v", target, err)
		}
		target.Name = "bad/name"
		if err := validateRequestTarget(target); err == nil {
			t.Fatalf("validateRequestTarget(%+v) succeeded", target)
		}
	}
	if err := validateRequestTarget(Target{Kind: "unknown", Owner: "acme", Name: "resource"}); err == nil {
		t.Fatal("unknown request target kind was accepted")
	}
}

func TestAdministrativeAttributeVocabulary(t *testing.T) {
	t.Parallel()
	valid := map[string]any{
		"max_bytes":          1024,
		"private":            "true",
		"ref_change":         "delete",
		"sdk":                "docker",
		"visibility":         "protected",
		"destination":        "acme/archive",
		"gating":             "manual",
		"factory_reboot":     "false",
		"hardware":           "a10g-small",
		"key":                "HF_TOKEN",
		"sleep_time_seconds": 300,
	}
	constraints, err := AttrConstraintsFromValues(valid)
	if err != nil || len(constraints) != len(valid) {
		t.Fatalf("AttrConstraintsFromValues() = %#v, %v", constraints, err)
	}
	if empty, err := AttrConstraintsFromValues(nil); err != nil || empty != nil {
		t.Fatalf("empty constraints = %#v, %v", empty, err)
	}

	invalid := []map[string]any{
		{"unknown": "value"},
		{"max_bytes": "large"},
		{"private": "sometimes"},
		{"ref_change": "rewrite"},
		{"sdk": "native"},
		{"visibility": "hidden"},
		{"gating": "sometimes"},
		{"destination": "missing-slash"},
		{"destination": strings.Repeat("x", MaxGlobBytes+1) + "/repo"},
		{"factory_reboot": "maybe"},
		{"hardware": 2},
		{"key": 2},
		{"sleep_time_seconds": "later"},
	}
	for _, attrs := range invalid {
		if _, err := AttrConstraintsFromValues(attrs); err == nil {
			t.Fatalf("AttrConstraintsFromValues(%#v) succeeded", attrs)
		}
	}
}

func TestValidateRequestCoversClosedRequestBoundary(t *testing.T) {
	valid := Request{Operation: OpRepoCreate, Target: Target{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "demo"}, Attrs: map[string]any{"visibility": "private"}}
	if err := ValidateRequest(valid); err != nil {
		t.Fatalf("ValidateRequest(valid) = %v", err)
	}
	tests := []Request{
		{Operation: "unknown", Target: valid.Target},
		{Operation: OpRepoCreate, Target: Target{Kind: KindBucket, Owner: "acme", Name: "demo"}},
		{Operation: OpRepoCreate, Target: Target{Kind: KindRepo, Type: TypeDataset, Owner: "bad/name", Name: "demo"}},
		{Operation: OpRepoCreate, Target: valid.Target, Attrs: map[string]any{"unknown": true}},
		{Operation: OpRepoCreate, Target: Target{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "demo", Refs: []string{"refs/*"}}},
	}
	for _, request := range tests {
		if err := ValidateRequest(request); err == nil {
			t.Fatalf("ValidateRequest(%+v) succeeded", request)
		}
	}
}

func TestGrantRequestAllowsOnlyBoundedPathAndKeyPrefixes(t *testing.T) {
	t.Parallel()
	request := Request{
		Operation: OpBucketObjectWrite,
		Target:    Target{Kind: KindBucket, Owner: "acme", Name: "artifacts", Keys: []string{"runs/**"}},
	}
	if err := ValidateGrantRequest(request); err != nil {
		t.Fatalf("ValidateGrantRequest() error = %v", err)
	}
	if err := ValidateRequest(request); err == nil {
		t.Fatal("executable request accepted a grant prefix constraint")
	}
	for _, key := range []string{"*", "runs/*/file", "runs/../?", strings.Repeat("x", MaxGlobBytes) + "/**"} {
		request.Target.Keys = []string{key}
		if err := ValidateGrantRequest(request); err == nil {
			t.Fatalf("ValidateGrantRequest() accepted %q", key)
		}
	}
}

func TestExactTargetConstraintsRejectEveryUnsafeShape(t *testing.T) {
	valid := Target{Refs: []string{"refs/heads/main"}, Paths: []string{"README.md"}, Keys: []string{"objects/item"}, Visibility: []string{"private"}}
	if err := validateExactTargetConstraints(valid); err != nil {
		t.Fatal(err)
	}
	for _, target := range []Target{
		{Refs: []string{""}},
		{Paths: []string{strings.Repeat("x", MaxGlobBytes+1)}},
		{Keys: []string{"objects/*"}},
		{Visibility: []string{"priv?te"}},
	} {
		if err := validateExactTargetConstraints(target); err == nil {
			t.Fatalf("unsafe target constraints accepted: %+v", target)
		}
	}
}

func TestPolicyParserBoundaryBranches(t *testing.T) {
	t.Parallel()
	var target TargetMatcher
	for _, raw := range []string{
		`{`,
		`{"kind":"repo","owner":"acme","name":"demo","unknown":true}`,
		`{"kind":"repo","owner":2,"name":"demo"}`,
	} {
		if err := json.Unmarshal([]byte(raw), &target); err == nil {
			t.Fatalf("UnmarshalJSON(%q) succeeded", raw)
		}
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("LoadFile accepted missing file")
	}
	file := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(file, []byte(`{"rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFile(file); err != nil {
		t.Fatalf("LoadFile(valid) = %v", err)
	}
	if _, err := Parse(make([]byte, MaxPolicyFileSizeBytes+1)); err == nil {
		t.Fatal("Parse accepted oversized policy")
	}
	if _, err := Parse([]byte(`{"rules":[]} {}`)); err == nil {
		t.Fatal("Parse accepted trailing content")
	}
	if _, err := buildPolicy(rawPolicy{Rules: make([]rawRule, MaxRules+1)}); err == nil {
		t.Fatal("buildPolicy accepted too many rules")
	}
	duplicate := rawRule{ID: "same", Effect: "allow", Clients: []string{"agent"}, Operations: []string{"repo.delete"},
		Targets: []TargetMatcher{{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "demo"}}}
	if _, err := buildPolicy(rawPolicy{Rules: []rawRule{duplicate, duplicate}}); err == nil {
		t.Fatal("buildPolicy accepted duplicate IDs")
	}

	if _, err := parseEffect("maybe"); err == nil {
		t.Fatal("parseEffect accepted unknown effect")
	}
	for _, clients := range [][]string{nil, make([]string, MaxClientsPerRule+1), {"bad client"}, {"same", "same"}} {
		if _, err := parseClients("clients", clients); err == nil {
			t.Fatalf("parseClients(%#v) succeeded", clients)
		}
	}
	for _, values := range [][]string{nil, make([]string, MaxOperationsPerRule+1), {"unknown.operation"}} {
		if _, err := parseOperations("operations", values); err == nil {
			t.Fatalf("parseOperations(%#v) succeeded", values)
		}
	}
	if _, err := parseTargets("targets", nil); err == nil {
		t.Fatal("parseTargets accepted empty targets")
	}
	if _, err := parseTargets("targets", make([]TargetMatcher, MaxTargetsPerRule+1)); err == nil {
		t.Fatal("parseTargets accepted too many targets")
	}

	invalidTargets := []TargetMatcher{
		{Kind: KindRepo, Type: "invalid", Owner: "acme", Name: "demo"},
		{Kind: KindRepo, Type: TypeDataset, Owner: "bad/name", Name: "demo"},
		{Kind: KindRepo, Type: TypeDataset, Owner: "acme", Name: "demo", Visibility: []string{"hidden"}, visibilitySet: true},
		{Kind: KindBucket, Type: TypeDataset, Owner: "acme", Name: "bucket"},
		{Kind: KindBucket, Owner: "bad/name", Name: "bucket"},
	}
	for _, invalid := range invalidTargets {
		candidate := invalid
		if err := validateTarget("target", &candidate); err == nil {
			t.Fatalf("validateTarget(%+v) succeeded", invalid)
		}
	}
	if err := validateGlob("ref", "refs/**/main", false); err == nil {
		t.Fatal("validateGlob accepted double star in ref")
	}
}

func TestAttributeAndGrantPolicyBoundaryBranches(t *testing.T) {
	t.Parallel()
	if AttrValuesMatch(map[string]any{"unknown": "value"}, nil) {
		t.Fatal("AttrValuesMatch accepted invalid approved attributes")
	}
	if _, err := AttrConstraintsFromValues(map[string]any{"key": make(chan int)}); err == nil {
		t.Fatal("AttrConstraintsFromValues accepted non-JSON value")
	}
	for _, raw := range []string{`-1`, `""`, `[]`, `[""]`, `true`} {
		if _, err := parseAttrValue(json.RawMessage(raw)); err == nil {
			t.Fatalf("parseAttrValue(%s) succeeded", raw)
		}
	}
	if err := validateAttrConstraint("future_attribute", AttrConstraint{}); err != nil {
		t.Fatalf("unknown future attribute constraint should be neutral: %v", err)
	}

	if _, err := parseGrantPolicy("grant", EffectAllow, []Operation{OpRepoCreate}, &rawGrantPolicy{}); err == nil {
		t.Fatal("allow rule accepted grant policy")
	}
	if _, err := parseGrantPolicy("grant", EffectRequest, []Operation{OpRepoCreate}, nil); err == nil {
		t.Fatal("request rule accepted missing grant policy")
	}
	invalidMode := "invalid"
	if _, err := normalizeGrantPolicy(&rawGrantPolicy{Mode: &invalidMode}, GrantModeExecution, []Operation{OpRepoCreate}); err == nil {
		t.Fatal("normalizeGrantPolicy accepted invalid mode")
	}
	if got, ok := int64Value(true); ok || got != 0 {
		t.Fatalf("int64Value(true) = %d, %v", got, ok)
	}
	if got := nonEmpty("", "fallback"); got != "fallback" {
		t.Fatalf("nonEmpty() = %q", got)
	}
}
