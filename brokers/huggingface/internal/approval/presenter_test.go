package approval

import (
	"context"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	bkgrants "github.com/osolmaz/brokerkit/grants"
	bkpolicy "github.com/osolmaz/brokerkit/policy"
)

func TestPresenterRendersSafeHFDetails(t *testing.T) {
	presentation, err := (Presenter{}).Present(context.Background(), bkgrants.Grant{
		ID: "grant-1", Operation: "git.push.force",
		Target:   bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}, "refs": {"refs/heads/main"}}},
		Metadata: map[string]string{"hf_grant_mode": "window"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if presentation.Risk != approvalview.RiskCritical || presentation.Target != "dataset/acme/demo" || len(presentation.Facts) != 3 || len(presentation.Warnings) != 1 {
		t.Fatalf("presentation = %+v", presentation)
	}
	if _, err := (Presenter{}).Present(context.Background(), bkgrants.Grant{ID: "missing"}); err == nil {
		t.Fatal("Present() accepted a grant without target")
	}
}

func TestPresenterUsesExactPlanProjection(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	presentation, err := (Presenter{}).Present(t.Context(), bkgrants.Grant{ID: "grant-1", Operation: "repo.delete",
		Target:   bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"kind": {"repo"}, "type": {"dataset"}, "owner": {"acme"}, "name": {"demo"}}},
		Metadata: map[string]string{hfplan.MetadataTitle: "Delete Hugging Face repository", hfplan.MetadataSummary: "Permanently delete dataset acme/demo", hfplan.MetadataDigest: digest}})
	if err != nil || presentation.Target != "dataset/acme/demo" || presentation.Title != "Delete Hugging Face repository" ||
		presentation.Summary != "Permanently delete dataset acme/demo" || presentation.PlanHash != digest {
		t.Fatalf("presentation = %+v, %v", presentation, err)
	}
}

func TestPresenterRiskClasses(t *testing.T) {
	for operation, want := range map[string]approvalview.Risk{
		"bucket.object.delete": approvalview.RiskCritical,
		"bucket.object.write":  approvalview.RiskHigh,
		"repo.contents.read":   approvalview.RiskLow,
		"custom.operation":     approvalview.RiskUnknown,
	} {
		if got := riskForOperation(operation); got != want {
			t.Fatalf("riskForOperation(%q) = %q, want %q", operation, got, want)
		}
	}
	for _, operation := range hfpolicy.Operations() {
		if got := riskForOperation(string(operation)); got == approvalview.RiskUnknown {
			t.Errorf("registered operation %q has no explicit risk", operation)
		}
	}
}

func TestPresenterCoversEveryRequestableOperation(t *testing.T) {
	for _, operation := range hfpolicy.Operations() {
		presentation, err := (Presenter{}).Present(t.Context(), bkgrants.Grant{
			ID: "grant-" + string(operation), Operation: string(operation),
			Target: bkpolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/acme/demo"}}},
		})
		if err != nil {
			t.Errorf("Present(%q) error = %v", operation, err)
			continue
		}
		if err := approvalview.Validate(presentation); err != nil {
			t.Errorf("Present(%q) produced invalid presentation: %v", operation, err)
		}
		if (presentation.Risk == approvalview.RiskHigh || presentation.Risk == approvalview.RiskCritical) && len(presentation.Warnings) == 0 {
			t.Errorf("Present(%q) omitted destructive warning", operation)
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
	last := presentation.Facts[len(presentation.Facts)-1]
	if last.Label != "Needs attention" || last.Value == "" {
		t.Fatalf("presentation = %+v", presentation)
	}
}
