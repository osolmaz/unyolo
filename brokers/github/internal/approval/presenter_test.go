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
	if presentation.Target != "osolmaz/gh-broker" || presentation.Risk != operatorinbox.RiskCritical || len(presentation.Fields) != 2 {
		t.Fatalf("presentation = %+v", presentation)
	}
}

func TestRiskUsesExplicitOperationTable(t *testing.T) {
	t.Parallel()
	if got := risk("git.push.force"); got != operatorinbox.RiskCritical {
		t.Fatalf("known risk = %q", got)
	}
	if got := risk("custom.force"); got != operatorinbox.RiskUnknown {
		t.Fatalf("unknown risk = %q", got)
	}
}
