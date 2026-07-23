package policypreset

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	shared "github.com/osolmaz/brokerkit/authorization/preset"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

func TestRenderRequestAllAgentOperations(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if artifacts.Manifest.OperationCounts != (OperationCounts{Total: 258, Allow: 8, Request: 140, Deny: 110}) {
		t.Fatalf("operation counts = %+v", artifacts.Manifest.OperationCounts)
	}
	if _, err := policy.Parse(artifacts.PolicyJSON); err != nil {
		t.Fatalf("rendered policy is invalid: %v", err)
	}
	assertRuleEffect(t, artifacts.PolicyJSON, "repo.contents.read", "allow")
	assertRuleEffect(t, artifacts.PolicyJSON, "repo.create", "request")
	assertRuleEffect(t, artifacts.PolicyJSON, "repo.delete", "request")
	assertRuleEffect(t, artifacts.PolicyJSON, "service_account.token.create", "deny")
	assertRuleEffect(t, artifacts.PolicyJSON, "sandbox.port.proxy", "deny")
	assertRuleEffect(t, artifacts.PolicyJSON, "auth.permission.check", "deny")
}

func TestRenderProtectedTargetsAsOverridingExactDenies(t *testing.T) {
	profile := NewProfile([]string{"agent"}, nil)
	profile.ProtectedTargets = []ProtectedTarget{{Kind: "bucket", Owner: "acme", Name: "mlclaw-state"}}
	artifacts, err := Render(profile)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := policy.Parse(artifacts.PolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	protected := policy.Request{Client: "agent", Operation: policy.OpBucketObjectWrite,
		Target: policy.Target{Kind: policy.KindBucket, Owner: "acme", Name: "mlclaw-state", Keys: []string{"state.json"}}}
	if decision := rendered.Decide(protected, nil, time.Now(), false); decision.Effect != policy.EffectDeny {
		t.Fatalf("protected decision = %+v", decision)
	}
	other := protected
	other.Target.Name = "artifacts"
	if decision := rendered.Decide(other, nil, time.Now(), false); len(decision.MatchedRequestRuleIDs) != 1 || decision.Reason != "approval_required" {
		t.Fatalf("ordinary decision = %+v", decision)
	}
	if !bytes.Contains(artifacts.ProfileJSON, []byte(`"protected_targets"`)) || Check(artifacts.ProfileJSON, artifacts.ManifestJSON, artifacts.PolicyJSON).Status != DriftCurrent {
		t.Fatal("protected target did not remain bound to managed artifacts")
	}
}

func TestRenderIsDeterministicAndNormalizesInputs(t *testing.T) {
	first, err := Render(NewProfile([]string{"worker", "agent"}, []string{"repo.delete", "repo.create"}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(NewProfile([]string{"agent", "worker"}, []string{"repo.create", "repo.delete"}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.ProfileJSON, second.ProfileJSON) || !bytes.Equal(first.PolicyJSON, second.PolicyJSON) || !bytes.Equal(first.ManifestJSON, second.ManifestJSON) {
		t.Fatal("equivalent profiles produced different artifacts")
	}
	if first.Manifest.OperationCounts.Request != 138 || first.Manifest.OperationCounts.Deny != 112 {
		t.Fatalf("override counts = %+v", first.Manifest.OperationCounts)
	}
	assertRuleEffect(t, first.PolicyJSON, "repo.create", "deny")
}

func TestFingerprintPreservesCatalogEffectUnderOperatorOverride(t *testing.T) {
	descriptor, found := opcatalog.ByName("repo.delete")
	if !found {
		t.Fatal("repo.delete missing from operation catalog")
	}
	overridden, err := Render(NewProfile([]string{"agent"}, []string{descriptor.Name}))
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(overridden.Manifest.Operations, func(operation OperationFingerprint) bool { return operation.Name == descriptor.Name })
	if index < 0 {
		t.Fatal("repo.delete missing from policy manifest")
	}
	fingerprint := overridden.Manifest.Operations[index]
	if fingerprint.DefaultEffect != descriptor.DefaultPolicyEffect || fingerprint.Effect != opcatalog.DefaultEffectDeny {
		t.Fatalf("overridden fingerprint = %+v", fingerprint)
	}
	if fingerprint.AuthorizationDigest == "" {
		t.Fatal("repo.delete authorization digest is empty")
	}
}

func TestProfileRejectsInvalidAndAmbiguousInputs(t *testing.T) {
	tests := []Profile{
		{},
		{Version: 2, Preset: RequestAllAgentOperations, Clients: []string{"agent"}},
		{Version: 1, Preset: "unknown", Clients: []string{"agent"}},
		NewProfile(nil, nil),
		NewProfile([]string{"agent", "agent"}, nil),
		NewProfile([]string{" agent"}, nil),
		NewProfile([]string{"agent"}, []string{"repo.unknown"}),
		NewProfile([]string{"agent"}, []string{"repo.delete", "repo.delete"}),
		{Version: 1, Preset: RequestAllAgentOperations, Clients: []string{"agent"}, ProtectedTargets: []ProtectedTarget{{Kind: "bucket", Owner: "acme", Name: "*"}}},
		{Version: 1, Preset: RequestAllAgentOperations, Clients: []string{"agent"}, ProtectedTargets: []ProtectedTarget{{Kind: "repo", Owner: "acme", Name: "state"}}},
		{Version: 1, Preset: RequestAllAgentOperations, Clients: []string{"agent"}, ProtectedTargets: []ProtectedTarget{{Kind: "inference", Owner: "acme", Name: "state"}}},
	}
	for _, profile := range tests {
		if _, err := Render(profile); err == nil {
			t.Fatalf("Render(%+v) accepted invalid profile", profile)
		}
	}
	if _, err := ParseProfile([]byte(`{"version":1,"preset":"request-all-agent-operations","clients":["agent"],"denied_operations":[],"extra":true}`)); err == nil {
		t.Fatal("ParseProfile accepted unknown field")
	}
}

func TestParseInstalledProfileDropsRetiredDenyOperations(t *testing.T) {
	data, err := shared.MarshalCanonical(Profile{
		Version: ProfileVersion, Preset: RequestAllAgentOperations, Clients: []string{"agent"},
		DeniedOperations: []string{"repo.delete", "repo.retired"},
	})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseInstalledProfile(data)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(profile.DeniedOperations, []string{"repo.delete"}) {
		t.Fatalf("current installed denies = %v", profile.DeniedOperations)
	}
}

func TestCatalogNeverDefaultsDangerousOperationsToAllow(t *testing.T) {
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.DefaultPolicyEffect != opcatalog.DefaultEffectAllow {
			continue
		}
		if descriptor.Risk == opcatalog.RiskHigh || descriptor.Risk == opcatalog.RiskCritical || descriptor.AuthorizationMode == opcatalog.ModeExecution || descriptor.ExplicitOnly || descriptor.Sealed || descriptor.Internal || descriptor.CredentialOutputKind != nil || !descriptor.AgentFacing {
			t.Fatalf("dangerous operation defaults to allow: %+v", descriptor)
		}
	}
}

func TestCheckReportsCurrentModifiedAndInvalidArtifacts(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	current := Check(artifacts.ProfileJSON, artifacts.ManifestJSON, artifacts.PolicyJSON)
	if current.Status != DriftCurrent {
		t.Fatalf("current report = %+v", current)
	}
	modifiedPolicy := append([]byte(nil), artifacts.PolicyJSON...)
	modifiedPolicy = bytes.Replace(modifiedPolicy, []byte("Generated by"), []byte("Rendered by"), 1)
	modified := Check(artifacts.ProfileJSON, artifacts.ManifestJSON, modifiedPolicy)
	if modified.Status != DriftModified || !strings.Contains(strings.Join(modified.Details, " "), "policy digest") {
		t.Fatalf("modified report = %+v", modified)
	}
	invalid := Check([]byte("{}"), artifacts.ManifestJSON, artifacts.PolicyJSON)
	if invalid.Status != DriftInvalid {
		t.Fatalf("invalid report = %+v", invalid)
	}
}

func TestCheckRequiresPolicyToMatchRenderedProfile(t *testing.T) {
	agentArtifacts, err := Render(NewProfile([]string{"agent"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	workerArtifacts, err := Render(NewProfile([]string{"worker"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	manifest := agentArtifacts.Manifest
	manifest.ProfileDigest = shared.Digest(workerArtifacts.ProfileJSON)
	manifestJSON, err := shared.MarshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	report := Check(workerArtifacts.ProfileJSON, manifestJSON, agentArtifacts.PolicyJSON)
	if report.Status != DriftModified || !strings.Contains(strings.Join(report.Details, " "), "deterministic render") {
		t.Fatalf("profile-policy mismatch report = %+v", report)
	}
}

func TestCheckReportsCatalogAndManifestDrift(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	stale := artifacts.Manifest
	stale.CatalogDigest = "sha256:" + strings.Repeat("0", 64)
	staleJSON, _ := shared.MarshalCanonical(stale)
	if report := Check(artifacts.ProfileJSON, staleJSON, artifacts.PolicyJSON); report.Status != DriftStale {
		t.Fatalf("stale report = %+v", report)
	}
	modified := artifacts.Manifest
	modified.Operations = slices.Clone(artifacts.Manifest.Operations)
	modified.Operations[0].OperationRevision++
	modifiedJSON, _ := shared.MarshalCanonical(modified)
	report := Check(artifacts.ProfileJSON, modifiedJSON, artifacts.PolicyJSON)
	if report.Status != DriftModified || len(report.ChangedOperations) != 1 {
		t.Fatalf("modified manifest report = %+v", report)
	}
}

func TestParseManifestRejectsMalformedArtifacts(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	wrongVersion := artifacts.Manifest
	wrongVersion.Version = 2
	wrongProvider := artifacts.Manifest
	wrongProvider.Provider = "github"
	missingDigest := artifacts.Manifest
	missingDigest.PolicyDigest = ""
	malformedCatalogDigest := artifacts.Manifest
	malformedCatalogDigest.CatalogDigest = "corrupt"
	malformedProfileDigest := artifacts.Manifest
	malformedProfileDigest.ProfileDigest = "sha256:1234"
	malformedPolicyDigest := artifacts.Manifest
	malformedPolicyDigest.PolicyDigest = "sha256:" + strings.Repeat("z", 64)
	wrongCount := artifacts.Manifest
	wrongCount.OperationCounts.Total--
	wrongEffectCount := artifacts.Manifest
	wrongEffectCount.OperationCounts.Allow--
	wrongEffectCount.OperationCounts.Request++
	negativeCount := artifacts.Manifest
	negativeCount.OperationCounts.Allow = -1
	invalidEffect := artifacts.Manifest
	invalidEffect.Operations = slices.Clone(artifacts.Manifest.Operations)
	invalidEffect.Operations[0].Effect = "invalid"
	invalidDefaultEffect := artifacts.Manifest
	invalidDefaultEffect.Operations = slices.Clone(artifacts.Manifest.Operations)
	invalidDefaultEffect.Operations[0].DefaultEffect = "invalid"
	duplicateOperation := artifacts.Manifest
	duplicateOperation.Operations = slices.Clone(artifacts.Manifest.Operations)
	duplicateOperation.Operations[0] = duplicateOperation.Operations[1]
	emptyOperation := artifacts.Manifest
	emptyOperation.Operations = slices.Clone(artifacts.Manifest.Operations)
	emptyOperation.Operations[0].Name = ""
	impossibleOverride := artifacts.Manifest
	impossibleOverride.Operations = slices.Clone(artifacts.Manifest.Operations)
	impossibleOverride.Operations[0].DefaultEffect = opcatalog.DefaultEffectDeny
	impossibleOverride.Operations[0].Effect = opcatalog.DefaultEffectAllow
	invalidRevision := artifacts.Manifest
	invalidRevision.Operations = slices.Clone(artifacts.Manifest.Operations)
	invalidRevision.Operations[0].OperationRevision = 0
	invalidAuthorizationDigest := artifacts.Manifest
	invalidAuthorizationDigest.Operations = slices.Clone(artifacts.Manifest.Operations)
	invalidAuthorizationDigest.Operations[0].AuthorizationDigest = "sha256:bad"
	tests := [][]byte{[]byte("{"), append(append([]byte(nil), artifacts.ManifestJSON...), []byte("{}")...)}
	for _, manifest := range []Manifest{
		wrongVersion, wrongProvider, missingDigest, malformedCatalogDigest, malformedProfileDigest,
		malformedPolicyDigest, wrongCount, wrongEffectCount, negativeCount,
		invalidEffect, invalidDefaultEffect, duplicateOperation, emptyOperation, impossibleOverride,
		invalidRevision, invalidAuthorizationDigest,
	} {
		data, _ := shared.MarshalCanonical(manifest)
		tests = append(tests, data)
	}
	for _, data := range tests {
		if _, err := ParseManifest(data); err == nil {
			t.Fatalf("parseManifest accepted %q", data)
		}
	}
}

func assertRuleEffect(t *testing.T, data []byte, operation, effect string) {
	t.Helper()
	var document struct {
		Rules []struct {
			Effect     string   `json:"effect"`
			Operations []string `json:"operations"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	for _, rule := range document.Rules {
		if len(rule.Operations) == 1 && rule.Operations[0] == operation {
			if rule.Effect != effect {
				t.Fatalf("%s effect = %q, want %q", operation, rule.Effect, effect)
			}
			return
		}
	}
	t.Fatalf("operation %s missing from policy containing %s", operation, strings.TrimSpace(string(data)))
}
