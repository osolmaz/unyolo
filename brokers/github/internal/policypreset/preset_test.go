package policypreset

import (
	"bytes"
	"slices"
	"testing"

	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/github/internal/opcatalog"
	"github.com/osolmaz/unyolo/brokers/github/internal/policy"
)

func TestRenderRequestAllAgentOperations(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent-a"}, nil))
	if err != nil {
		t.Fatal(err)
	}
	want := OperationCounts{Total: 1445, Allow: 614, Request: 521, Deny: 310}
	if artifacts.Manifest.Provider != "github" || artifacts.Manifest.OperationCounts != want {
		t.Fatalf("manifest = %+v, want provider github and counts %+v", artifacts.Manifest, want)
	}
	rendered, err := policy.Parse(artifacts.PolicyJSON)
	if err != nil {
		t.Fatalf("rendered policy is invalid: %v", err)
	}
	repo := policy.Target{Kind: "repo", Owner: "acme", Name: "private"}
	fetch := policy.Request{Client: "agent-a", Operation: policy.OperationGitFetch, Target: repo}
	if decision := rendered.EvaluateAnonymous(fetch); !decision.Allowed || decision.CredentialUse != corepolicy.CredentialUseNone {
		t.Fatalf("anonymous fetch decision = %+v", decision)
	}
	if decision := rendered.Evaluate(fetch); !decision.Allowed || decision.CredentialUse != corepolicy.CredentialUseManaged {
		t.Fatalf("managed fetch decision = %+v", decision)
	}
	push := policy.Request{Client: "agent-a", Operation: policy.OperationGitPushBranchCreate, Target: repo,
		Attrs: map[string]string{"ref": "refs/heads/topic"}}
	if decision := rendered.EvaluateGrantRequest(push); decision.Effect != policy.EffectRequest || decision.GrantPolicy == nil {
		t.Fatalf("push decision = %+v", decision)
	}
	assertEffect(t, artifacts, "repo.contents.read", "allow")
	assertEffect(t, artifacts, "graphql.read", "allow")
	assertEffect(t, artifacts, "git.push.force", "request")
	assertEffect(t, artifacts, "repo.delete", "request")
	assertEffect(t, artifacts, "pull_request.merge_admin", "request")
}

// TestProtocolOperationsMatchTheirRESTEquivalents keeps Git, GraphQL, and REST
// consistent: an agent gets the same default answer for the same data.
func TestProtocolOperationsMatchTheirRESTEquivalents(t *testing.T) {
	equivalents := map[policy.Operation][]string{
		policy.OperationGitFetch:            {"repo.contents.read", "repo.download_tarball_archive", "git.get_blob"},
		policy.OperationGitLFSWrite:         {"repo.create_or_update_file_contents"},
		policy.OperationGitPushAdvertise:    {"git.list_matching_refs", "branch.repos_list_branches"},
		policy.OperationGitPushBranchCreate: {"git.create_ref"},
		policy.OperationGitPushFastForward:  {"git.update_ref"},
		policy.OperationGitPushForce:        {"git.update_ref"},
		policy.OperationGitRefDelete:        {"git.delete_ref"},
		policy.OperationGitTagUpdate:        {"git.create_ref", "git.update_ref"},
		policy.OperationGraphQLRead:         {"repo.contents.read", "pull_request.list", "issue.issues_list_for_repo"},
	}
	if len(equivalents) != len(protocolOperations) {
		t.Fatalf("equivalents cover %d protocol operations, want %d", len(equivalents), len(protocolOperations))
	}
	for _, protocol := range protocolOperations {
		names, found := equivalents[protocol.name]
		if !found {
			t.Fatalf("protocol operation %s has no REST equivalent", protocol.name)
		}
		for _, name := range names {
			descriptor, found := opcatalog.ByName(name)
			if !found || descriptor.DefaultPolicyEffect != protocol.effect {
				t.Errorf("%s defaults to %s, but its REST equivalent %s defaults to %s", protocol.name, protocol.effect, name, descriptor.DefaultPolicyEffect)
			}
		}
	}
}

func TestEveryAgentProtocolOperationHasAPresetEffect(t *testing.T) {
	registry, err := policy.CatalogRegistry()
	if err != nil {
		t.Fatal(err)
	}
	for name := range registry.Operations {
		if _, catalog := opcatalog.ByName(name); catalog || name == string(policy.OperationWebhookGitHubReceive) {
			continue
		}
		if !isProtocolOperation(name) {
			t.Errorf("protocol operation %s has no preset effect", name)
		}
	}
}

func TestDeniedProtocolOperationBlocksAnonymousUse(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent-a"}, []string{"git.fetch"}))
	if err != nil {
		t.Fatal(err)
	}
	assertEffect(t, artifacts, "git.fetch", "deny")
	rendered, err := policy.Parse(artifacts.PolicyJSON)
	if err != nil {
		t.Fatal(err)
	}
	fetch := policy.Request{Client: "agent-a", Operation: policy.OperationGitFetch,
		Target: policy.Target{Kind: "repo", Owner: "acme", Name: "public"}}
	if decision := rendered.EvaluateAnonymous(fetch); decision.Allowed {
		t.Fatalf("denied fetch was allowed anonymously: %+v", decision)
	}
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

func TestParseProfileRoundTrip(t *testing.T) {
	artifacts, err := Render(NewProfile([]string{"agent-a"}, []string{"repo.delete"}))
	if err != nil {
		t.Fatal(err)
	}
	profile, err := ParseProfile(artifacts.ProfileJSON)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(profile.Clients, []string{"agent-a"}) || !slices.Equal(profile.DeniedOperations, []string{"repo.delete"}) {
		t.Fatalf("profile = %+v", profile)
	}
	if _, err := ParseProfile([]byte(`{"version":1,"provider":"github","preset":"wrong"}`)); err == nil {
		t.Fatal("invalid preset accepted")
	}
}

func TestCatalogNeverDefaultsDangerousOperationsToAllow(t *testing.T) {
	for _, descriptor := range opcatalog.MustAll() {
		if descriptor.DefaultPolicyEffect != opcatalog.DefaultEffectAllow {
			continue
		}
		if descriptor.Risk == opcatalog.RiskHigh || descriptor.Risk == opcatalog.RiskCritical || descriptor.HasExecutionDisposition() || descriptor.ExplicitOnly || descriptor.Sealed || descriptor.Internal || descriptor.CredentialOutputKind != nil || !descriptor.AgentFacing {
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

func TestProfileWithoutClientsRendersAValidEmptyPolicy(t *testing.T) {
	artifacts, err := Render(NewProfile(nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := (renderer{}).ValidatePolicy(artifacts.PolicyJSON); err != nil {
		t.Fatalf("policy without clients is invalid: %v", err)
	}
	if report := Check(artifacts.ProfileJSON, artifacts.ManifestJSON, artifacts.PolicyJSON); report.Status != DriftCurrent {
		t.Fatalf("drift report for a profile without clients = %+v", report)
	}
}
