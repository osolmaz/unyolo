package approval

import (
	"context"
	"testing"

	bkgrants "github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
)

func TestPresenterRendersSafeHFDetails(t *testing.T) {
	presentation, err := (Presenter{}).Present(context.Background(), bkgrants.Grant{
		ID: "grant-1", Operation: "git.push.force",
		Target:   bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "ref": {"refs/heads/main"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if presentation.Risk != operatorinbox.RiskCritical || presentation.Target != "dataset/acme/demo" || len(presentation.Fields) != 3 {
		t.Fatalf("presentation = %+v", presentation)
	}
	if _, err := (Presenter{}).Present(context.Background(), bkgrants.Grant{ID: "missing"}); err == nil {
		t.Fatal("Present() accepted a grant without target")
	}
}

func TestPresenterRiskClasses(t *testing.T) {
	for operation, want := range map[string]operatorinbox.Risk{
		"bucket.object.delete": operatorinbox.RiskCritical,
		"bucket.object.write":  operatorinbox.RiskHigh,
		"repo.contents.read":   operatorinbox.RiskLow,
		"custom.operation":     operatorinbox.RiskMedium,
	} {
		if got := riskForOperation(operation); got != want {
			t.Fatalf("riskForOperation(%q) = %q, want %q", operation, got, want)
		}
	}
}
