package opcatalog

import (
	"bytes"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/operation/capability"
)

func TestCatalogValidatesAndContainsCanonicalOperations(t *testing.T) {
	values, err := All()
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != ExpectedCount {
		t.Fatalf("catalog count=%d", len(values))
	}
	for _, name := range []string{"repo.metadata.read", "repo.contents.read", "repo.visibility.update", "pull_request.create", "pull_request.merge", "pull_request.merge_admin", "installation.repo.list"} {
		value, found := ByName(name)
		if !found {
			t.Fatalf("operation %q missing", name)
		}
		if name == "repo.visibility.update" || name == "pull_request.merge" || name == "pull_request.merge_admin" {
			if !value.ExplicitOnly || value.Risk != RiskHigh || value.MaxUses != 1 {
				t.Fatalf("high-risk descriptor=%+v", value)
			}
		}
	}
	for _, descriptor := range values {
		if descriptor.AuthorizationMode == ModeWindow && (descriptor.MaxUses != int(usebudget.MaxFiniteUses) || descriptor.ApprovalTTLSeconds != 7*24*60*60) {
			t.Fatalf("routine window operation %s = %+v", descriptor.Name, descriptor)
		}
	}
	for _, removed := range []string{"pr.create", "pr.update", "pr.merge", "contents.read", "checks.read", "http.request", "graphql.execute"} {
		if _, found := ByName(removed); found {
			t.Fatalf("legacy or raw operation %q survived", removed)
		}
	}
}

func TestGeneratedRESTCredentialAndRiskClassification(t *testing.T) {
	for _, name := range []string{
		"installation.apps_list_installations_for_authenticated_user",
		"notification.activity_list_notifications_for_authenticated_user",
		"issue.issues_list_for_authenticated_user",
	} {
		descriptor, found := ByName(name)
		if !found || descriptor.CredentialKind != "user" {
			t.Fatalf("%s credential = %q, want user", name, descriptor.CredentialKind)
		}
	}
	descriptor, found := ByName("issue.issues_create")
	if !found || descriptor.Risk != RiskMedium || descriptor.ExplicitOnly || descriptor.FamilyGlobAllowed == false {
		t.Fatalf("ordinary mutation classification = %+v", descriptor)
	}
	for _, descriptor := range MustAll() {
		if descriptor.AgentFacing && descriptor.CredentialKind == "installation" && len(descriptor.RequiredGitHubPermissions) == 0 && !descriptor.AllowEmptyInstallationPermissions {
			t.Fatalf("agent-facing installation operation %q has no reviewed permissions", descriptor.Name)
		}
	}
	for _, name := range []string{"app.meta_get", "release.repos_upload_release_asset"} {
		descriptor, found := ByName(name)
		if !found || descriptor.CredentialKind != "user" {
			t.Fatalf("%s credential = %q, want user", name, descriptor.CredentialKind)
		}
	}
	installation, found := ByName("installation.repo.list")
	if !found || installation.CredentialKind != "installation" || !installation.AllowEmptyInstallationPermissions {
		t.Fatalf("permissionless installation credential = %+v", installation)
	}
}

func TestPersistedGraphQLRequiresReviewedTargetBindings(t *testing.T) {
	count := 0
	for _, descriptor := range MustAll() {
		if descriptor.ExecutorKind != "persisted-graphql" {
			continue
		}
		count++
		if descriptor.AgentFacing || descriptor.MCPTool != nil || descriptor.CLICommand != nil {
			t.Fatalf("unbound GraphQL operation %q is agent-facing", descriptor.Name)
		}
		if descriptor.Implementation != capability.StatusOperatorOnly && descriptor.Implementation != capability.StatusInternal {
			t.Fatalf("unbound GraphQL operation %q has status %q", descriptor.Name, descriptor.Implementation)
		}
	}
	if count != 283 {
		t.Fatalf("unbound persisted GraphQL operations=%d, want 283", count)
	}
	admin, found := ByName("pull_request.merge_admin")
	if !found || admin.ExecutorKind != "admin-merge" || !admin.DelegatedUserCredential || admin.CredentialKind != "user" || !admin.AgentFacing {
		t.Fatalf("reviewed admin merge descriptor = %+v", admin)
	}
}

func TestGeneratedCapabilityJSONMatchesCatalog(t *testing.T) {
	data, err := os.ReadFile("../../docs/generated/capabilities.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(data), bytes.TrimSpace(raw)) {
		t.Fatal("generated capability JSON is stale")
	}
}

func TestEveryGitHubOperationHasReviewedDefaultPolicyEffect(t *testing.T) {
	counts := map[capability.DefaultPolicyEffect]int{}
	for _, descriptor := range MustAll() {
		counts[descriptor.DefaultPolicyEffect]++
		if (!descriptor.AgentFacing || descriptor.CredentialOutputKind != nil) && descriptor.DefaultPolicyEffect != capability.DefaultEffectDeny {
			t.Fatalf("non-agent or credential-output operation %q is not denied", descriptor.Name)
		}
		if descriptor.DefaultPolicyEffect == capability.DefaultEffectAllow && (descriptor.Risk != capability.RiskLow || descriptor.ExplicitOnly) {
			t.Fatalf("unsafe operation %q is allowed by default", descriptor.Name)
		}
	}
	want := map[capability.DefaultPolicyEffect]int{
		capability.DefaultEffectAllow: 611, capability.DefaultEffectRequest: 515, capability.DefaultEffectDeny: 310,
	}
	if !maps.Equal(counts, want) {
		t.Fatalf("default policy counts = %v, want %v", counts, want)
	}
}

func TestRunnerTokensUseEncryptedCredentialOutputs(t *testing.T) {
	for _, name := range []string{
		"runner.actions_create_registration_token_for_org",
		"runner.actions_create_registration_token_for_repo",
		"runner.actions_create_remove_token_for_org",
		"runner.actions_create_remove_token_for_repo",
	} {
		descriptor, found := ByName(name)
		if !found || descriptor.CredentialOutputKind == nil || *descriptor.CredentialOutputKind != "github-runner-token" ||
			!descriptor.Sealed || !descriptor.ExplicitOnly || !descriptor.AgentFacing {
			t.Fatalf("runner credential descriptor %q = %+v", name, descriptor)
		}
	}
}

func TestGitHubCatalogValidationFailsClosed(t *testing.T) {
	valid := MustAll()
	tests := []struct {
		name   string
		mutate func([]Descriptor)
	}{
		{"summary", func(values []Descriptor) { values[0].Summary = "" }},
		{"schema", func(values []Descriptor) { values[0].TargetSchema = "" }},
		{"credential", func(values []Descriptor) { values[0].CredentialKind = "raw-token" }},
		{"permissionless installation", func(values []Descriptor) { values[0].AllowEmptyInstallationPermissions = true }},
		{"binding", func(values []Descriptor) { values[0].UpstreamBindingIDs = nil }},
		{"sealed paths", func(values []Descriptor) {
			for index := range values {
				if values[index].Sealed {
					values[index].SealedInputPaths = nil
					return
				}
			}
		}},
		{"high risk", func(values []Descriptor) {
			for index := range values {
				if values[index].Risk == RiskHigh && values[index].AuthorizationMode == ModeExecution {
					values[index].ExplicitOnly = false
					values[index].Disposition = strings.ReplaceAll(values[index].Disposition, "X", "")
					return
				}
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := slices.Clone(valid)
			test.mutate(values)
			if err := Validate(values); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}
