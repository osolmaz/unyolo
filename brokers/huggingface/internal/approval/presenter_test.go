package approval

import (
	"context"
	"testing"

	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
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
		"custom.operation":     operatorinbox.RiskUnknown,
	} {
		if got := riskForOperation(operation); got != want {
			t.Fatalf("riskForOperation(%q) = %q, want %q", operation, got, want)
		}
	}
	for _, operation := range hfpolicy.Operations() {
		if got := riskForOperation(string(operation)); got == operatorinbox.RiskUnknown {
			t.Errorf("registered operation %q has no explicit risk", operation)
		}
	}
}

func TestPresenterShowsAmbiguousExecutionWithoutInternalCounters(t *testing.T) {
	presentation, err := (Presenter{}).Present(t.Context(), bkgrants.Grant{
		ID: "grant-1", Operation: string(hfpolicy.OpGitPushAppend), ReservationRetained: true, ReservedCount: 1,
		Target: bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	last := presentation.Fields[len(presentation.Fields)-1]
	if last.Label != "Needs attention" || last.Value == "" {
		t.Fatalf("presentation = %+v", presentation)
	}
}
