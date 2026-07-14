package approval

import (
	"context"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

func TestPresenter(t *testing.T) {
	presentation, err := (Presenter{}).Present(context.Background(), grants.Grant{
		ID: "grant-1", Operation: "git.push.force",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"gh-broker"}}},
		Attrs:  map[string][]string{"ref": {"refs/heads/main"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if presentation.Target != "osolmaz/gh-broker" || presentation.Risk != operatorinbox.RiskCritical || len(presentation.Fields) != 5 {
		t.Fatalf("presentation = %+v", presentation)
	}
}

func TestPresenterShowsConcreteGeneratedTargetsAndSecurityAttributes(t *testing.T) {
	t.Parallel()
	grant := grants.Grant{
		ID: "grant-2", Operation: "action_run.actions_cancel_workflow_run",
		Target: policy.Target{Kind: "run", Fields: map[string][]string{
			"owner": {"osolmaz"}, "name": {"brokerkit"}, "id": {"123"},
		}},
		Attrs: map[string][]string{"workflow_ref": {"deploy.yml@main"}, "environment": {"production"}},
	}
	presentation, err := (Presenter{}).Present(t.Context(), grant)
	if err != nil {
		t.Fatal(err)
	}
	if presentation.Target != "run osolmaz/brokerkit 123" {
		t.Fatalf("target = %q", presentation.Target)
	}
	want := map[string]string{"Target": presentation.Target, "Target owner": "osolmaz", "Target name": "brokerkit", "Target ID": "123",
		"Environment": "production", "Workflow ref": "deploy.yml@main"}
	for _, field := range presentation.Fields {
		if expected, found := want[field.Label]; found {
			if field.Value != expected {
				t.Fatalf("%s = %q, want %q", field.Label, field.Value, expected)
			}
			delete(want, field.Label)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing approval fields: %+v", want)
	}
}

func TestPresenterShowsGeneratedPathSelectors(t *testing.T) {
	presentation, err := (Presenter{}).Present(t.Context(), grants.Grant{
		ID: "grant-selector", Operation: "collaborator.orgs_remove_outside_collaborator",
		Target: policy.Target{Kind: "organization", Fields: map[string][]string{"name": {"acme"}}},
		Attrs:  map[string][]string{"selector_username": {"octocat"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range presentation.Fields {
		if field.Label == "Selector username" && field.Value == "octocat" {
			return
		}
	}
	t.Fatalf("presentation = %+v", presentation)
}

func TestTargetSummaryRejectsKindOnlyAndFormatsNamedTargets(t *testing.T) {
	t.Parallel()
	if got := TargetSummary(policy.Target{Kind: "user"}); got != "" {
		t.Fatalf("kind-only target = %q", got)
	}
	if got := TargetSummary(policy.Target{Kind: "user", Fields: map[string][]string{"name": {"octocat"}}}); got != "user octocat" {
		t.Fatalf("user target = %q", got)
	}
	if got := TargetSummary(policy.Target{Kind: "issue", Fields: map[string][]string{
		"owner": {"osolmaz"}, "name": {"brokerkit"}, "number": {"38"},
	}}); got != "issue osolmaz/brokerkit #38" {
		t.Fatalf("issue target = %q", got)
	}
}

func TestRiskUsesGeneratedCatalogAndProtocolTable(t *testing.T) {
	t.Parallel()
	if got := risk("git.push.force"); got != operatorinbox.RiskCritical {
		t.Fatalf("protocol risk = %q", got)
	}
	if got := risk("repo.delete"); got != operatorinbox.RiskCritical {
		t.Fatalf("catalog risk = %q", got)
	}
	if got := risk("custom.force"); got != operatorinbox.RiskUnknown {
		t.Fatalf("unknown risk = %q", got)
	}
}
