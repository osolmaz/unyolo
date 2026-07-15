package policypreset

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

type testRenderer struct {
	provider   string
	operations []Operation
	invalid    bool
}

func (r testRenderer) ProviderID() string { return r.provider }
func (testRenderer) PresetName() string   { return "request-all-agent-operations" }
func (r testRenderer) Operations() ([]Operation, error) {
	return r.operations, nil
}
func (testRenderer) RenderPolicy(profile Profile, operations []EffectiveOperation) ([]byte, error) {
	return MarshalCanonical(struct {
		Clients    []string             `json:"clients"`
		Operations []EffectiveOperation `json:"operations"`
	}{Clients: profile.Clients, Operations: operations})
}
func (r testRenderer) ValidatePolicy(data []byte) error {
	if r.invalid || !bytes.HasPrefix(data, []byte("{")) {
		return errors.New("invalid test policy")
	}
	return nil
}

func TestLifecycleIsDeterministicAndPreservesDenies(t *testing.T) {
	renderer := fixtureRenderer("provider-a")
	first, err := Render(renderer, NewProfile(renderer, []string{"worker", "agent-a"}, []string{"repo.delete"}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(renderer, NewProfile(renderer, []string{"agent-a", "worker"}, []string{"repo.delete"}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.ProfileJSON, second.ProfileJSON) || !bytes.Equal(first.PolicyJSON, second.PolicyJSON) || !bytes.Equal(first.ManifestJSON, second.ManifestJSON) {
		t.Fatal("equivalent input produced different artifacts")
	}
	wantCounts := OperationCounts{Total: 2, Allow: 1, Deny: 1}
	if first.Manifest.Provider != "provider-a" || first.Manifest.OperationCounts != wantCounts || first.Manifest.Operations[1].Effect != EffectDeny {
		t.Fatalf("manifest = %+v", first.Manifest)
	}
	if report := Check(renderer, first.ProfileJSON, first.ManifestJSON, first.PolicyJSON); report.Status != DriftCurrent {
		t.Fatalf("current report = %+v", report)
	}
}

func TestLifecycleRejectsCrossProviderAndModifiedArtifacts(t *testing.T) {
	renderer := fixtureRenderer("provider-a")
	artifacts, err := Render(renderer, NewProfile(renderer, []string{"agent-a"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseManifest(fixtureRenderer("provider-b"), artifacts.ManifestJSON); err == nil {
		t.Fatal("cross-provider manifest accepted")
	}
	modified := append([]byte(nil), artifacts.PolicyJSON...)
	modified = bytes.Replace(modified, []byte("agent-a"), []byte("agent-b"), 1)
	report := Check(renderer, artifacts.ProfileJSON, artifacts.ManifestJSON, modified)
	if report.Status != DriftModified || !strings.Contains(strings.Join(report.Details, " "), "policy digest") {
		t.Fatalf("modified report = %+v", report)
	}
	if report := Check(renderer, []byte("{}"), artifacts.ManifestJSON, artifacts.PolicyJSON); report.Status != DriftInvalid {
		t.Fatalf("invalid report = %+v", report)
	}
}

func TestLifecycleReportsCatalogChangesAndDropsRetiredDenies(t *testing.T) {
	oldRenderer := fixtureRenderer("provider-a")
	old, err := Render(oldRenderer, NewProfile(oldRenderer, []string{"agent-a"}, []string{"repo.delete"}))
	if err != nil {
		t.Fatal(err)
	}
	currentRenderer := fixtureRenderer("provider-a")
	currentRenderer.operations = []Operation{
		currentRenderer.operations[0],
		{Name: "repo.rename", OperationRevision: 1, DefaultEffect: EffectRequest, AuthorizationDigest: testDigest("rename")},
	}
	report := Check(currentRenderer, old.ProfileJSON, old.ManifestJSON, old.PolicyJSON)
	if report.Status != DriftStale || !slices.Equal(report.AddedOperations, []string{"repo.rename"}) || !slices.Equal(report.RemovedOperations, []string{"repo.delete"}) {
		t.Fatalf("catalog report = %+v", report)
	}
	profile, err := ParseInstalledProfile(currentRenderer, old.ProfileJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.DeniedOperations) != 0 {
		t.Fatalf("retired denies = %v", profile.DeniedOperations)
	}
}

func TestLifecycleDetectsAuthorizationFingerprintChanges(t *testing.T) {
	renderer := fixtureRenderer("provider-a")
	artifacts, err := Render(renderer, NewProfile(renderer, []string{"agent-a"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	renderer.operations[0].AuthorizationDigest = testDigest("changed authorization")
	report := Check(renderer, artifacts.ProfileJSON, artifacts.ManifestJSON, artifacts.PolicyJSON)
	if report.Status != DriftStale || !slices.Equal(report.ChangedOperations, []string{"repo.contents.read"}) {
		t.Fatalf("authorization drift report = %+v", report)
	}
}

func TestLifecycleRejectsMalformedInputs(t *testing.T) {
	renderer := fixtureRenderer("provider-a")
	badOperations := fixtureRenderer("provider-a")
	badOperations.operations[0].AuthorizationDigest = "sha256:bad"
	for _, input := range []struct {
		renderer testRenderer
		profile  Profile
	}{
		{renderer, Profile{}},
		{renderer, NewProfile(renderer, nil, nil)},
		{renderer, NewProfile(renderer, []string{" agent-a"}, nil)},
		{renderer, NewProfile(renderer, []string{"agent-a"}, []string{"unknown.operation"})},
		{badOperations, NewProfile(badOperations, []string{"agent-a"}, nil)},
	} {
		if _, err := Render(input.renderer, input.profile); err == nil {
			t.Fatalf("Render(%+v) accepted malformed input", input.profile)
		}
	}
}

func fixtureRenderer(provider string) testRenderer {
	return testRenderer{provider: provider, operations: []Operation{
		{Name: "repo.contents.read", OperationRevision: 1, DefaultEffect: EffectAllow, AuthorizationDigest: testDigest("read")},
		{Name: "repo.delete", OperationRevision: 1, DefaultEffect: EffectRequest, AuthorizationDigest: testDigest("delete")},
	}}
}

func testDigest(value string) string { return Digest([]byte(value)) }
