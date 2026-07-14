package policypreset

import (
	"bytes"
	"slices"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/brokers/github/internal/policy"
)

func TestRenderRequestAllAgentOperations(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent-a"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := OperationCounts{Total: 1436, Allow: 611, Request: 514, Deny: 311}
	if artifacts.Manifest.Provider != "github" || artifacts.Manifest.OperationCounts != want {
		t.Fatalf("manifest = %+v, want provider github and counts %+v", artifacts.Manifest, want)
	}
	if _, err := policy.Parse(artifacts.PolicyJSON); err != nil {
		t.Fatalf("rendered policy is invalid: %v", err)
	}
	assertEffect(t, artifacts, "repo.contents.read", "allow")
	assertEffect(t, artifacts, "repo.delete", "request")
}

func TestRenderNormalizesAndPreservesDenyOverrides(t *testing.T) {
	first, err := Render(NewProfile([]string{"worker", "agent-a"}, []string{"repo.delete", "pull_request.create"}))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Render(NewProfile([]string{"agent-a", "worker"}, []string{"pull_request.create", "repo.delete"}))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.ProfileJSON, second.ProfileJSON) || !bytes.Equal(first.PolicyJSON, second.PolicyJSON) || !bytes.Equal(first.ManifestJSON, second.ManifestJSON) {
		t.Fatal("equivalent profiles produced different artifacts")
	}
	assertEffect(t, first, "repo.delete", "deny")
	if report := Check(first.ProfileJSON, first.ManifestJSON, first.PolicyJSON); report.Status != DriftCurrent {
		t.Fatalf("drift report = %+v", report)
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

func assertEffect(t *testing.T, artifacts Artifacts, name string, want string) {
	t.Helper()
	index := slices.IndexFunc(artifacts.Manifest.Operations, func(operation OperationFingerprint) bool { return operation.Name == name })
	if index < 0 {
		t.Fatalf("operation %s missing", name)
	}
	if got := string(artifacts.Manifest.Operations[index].Effect); got != want {
		t.Fatalf("operation %s effect = %s, want %s", name, got, want)
	}
}
