package approval

import (
	"context"
	"testing"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/grants"
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
	if presentation.Target != "osolmaz/gh-broker" || presentation.Risk != approvalview.RiskCritical || len(presentation.Facts) != 5 || len(presentation.Warnings) != 1 {
		t.Fatalf("presentation = %+v", presentation)
	}
}

func TestPresenterShowsConcreteGeneratedTargetsAndSecurityAttributes(t *testing.T) {
	t.Parallel()
	grant := grants.Grant{
		ID: "grant-2", Operation: "action_run.actions_cancel_workflow_run",
		Target: policy.Target{Kind: "run", Fields: map[string][]string{
			"owner": {"osolmaz"}, "repo": {"brokerkit"}, "id": {"123"},
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
	want := map[string]string{"Target": presentation.Target, "Target owner": "osolmaz", "Target repository": "brokerkit", "Target ID": "123",
		"Environment": "production", "Workflow ref": "deploy.yml@main"}
	for _, field := range presentation.Facts {
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
	for _, field := range presentation.Facts {
		if field.Label == "Selector username" && field.Value == "octocat" {
			return
		}
	}
	t.Fatalf("presentation = %+v", presentation)
}

func TestPresenterShowsInstallationAndCreatedResourceSelectors(t *testing.T) {
	presentation, err := (Presenter{}).Present(t.Context(), grants.Grant{
		ID: "grant-installation", Operation: "repo.create_using_template",
		Target: policy.Target{Kind: "installation", Fields: map[string][]string{"installation_id": {"42"}}},
		Attrs:  map[string][]string{"resource_owner": {"osolmaz"}, "resource_name": {"brokerkit-next"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"Installation ID": "42", "Resource owner": "osolmaz", "Resource name": "brokerkit-next"}
	for _, field := range presentation.Facts {
		if expected, found := want[field.Label]; found && field.Value == expected {
			delete(want, field.Label)
		}
	}
	if presentation.Target != "installation 42" || len(want) != 0 {
		t.Fatalf("presentation = %+v, missing = %+v", presentation, want)
	}
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
		"owner": {"osolmaz"}, "repo": {"brokerkit"}, "number": {"38"},
	}}); got != "issue osolmaz/brokerkit #38" {
		t.Fatalf("issue target = %q", got)
	}
}

func TestRiskUsesGeneratedCatalogAndProtocolTable(t *testing.T) {
	t.Parallel()
	if got := risk("git.push.force"); got != approvalview.RiskCritical {
		t.Fatalf("protocol risk = %q", got)
	}
	if got := risk("repo.delete"); got != approvalview.RiskCritical {
		t.Fatalf("catalog risk = %q", got)
	}
	if got := risk("custom.force"); got != approvalview.RiskUnknown {
		t.Fatalf("unknown risk = %q", got)
	}
}
