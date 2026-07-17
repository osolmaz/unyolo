package approvalnotify

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/usebudget"
)

func TestProjectAndMemory(t *testing.T) {
	grant := grants.Grant{ID: "grant-1", Client: "agent-a", Operation: "repo.delete", Reason: "cleanup",
		Duration: 5 * time.Minute, MaxUses: 1, PendingExpiresAt: time.Unix(10, 0)}
	approval := Project(t.Context(), "GitHub", approvalview.PresenterFunc(func(context.Context, grants.Grant) (approvalview.Presentation, error) {
		return approvalview.Presentation{Risk: approvalview.RiskCritical, Title: "Delete repository", Target: "example/repo"}, nil
	}), grant, "secret-token")
	if approval.Broker != "GitHub" || approval.RequestedDurationSeconds != 300 || approval.Presentation.Target != "example/repo" {
		t.Fatalf("Project() = %+v", approval)
	}
	notifier := &Memory{}
	ref, err := notifier.SendApproval(t.Context(), approval)
	if err != nil || ref.PresentationJSON == "" || ref.PresentationDigest == "" || notifier.Messages[0].DecisionToken != "" {
		t.Fatalf("SendApproval() = %+v, messages=%+v, err=%v", ref, notifier.Messages, err)
	}
	status := notify.Status{Kind: notify.StatusActive, MaxUses: usebudget.Limit(1)}
	if err := notifier.UpdateStatus(t.Context(), ref, status); err != nil || notifier.Statuses[0] != status {
		t.Fatalf("UpdateStatus() statuses=%+v err=%v", notifier.Statuses, err)
	}
}

func TestPresentationDigestIsStableAndSecretFree(t *testing.T) {
	approval := Approval{Broker: "GitHub", Requester: "agent-a", Operation: "repo.delete", Reason: "cleanup",
		Presentation:  approvalview.Presentation{Risk: approvalview.RiskHigh, Title: "Delete", Target: "example/repo"},
		DecisionToken: "secret-a"}
	first := PresentationDigest(approval)
	snapshot := SnapshotJSON(approval)
	approval.DecisionToken = "secret-b"
	if first == "" || PresentationDigest(approval) != first || SnapshotJSON(approval) != snapshot {
		t.Fatalf("digest changed with decision token: %q", first)
	}
	if strings.Contains(snapshot, "secret-a") {
		t.Fatal("semantic snapshot retained the decision token")
	}
}

func TestSnapshotAvoidsHTMLExpansionAndProjectBoundsRequester(t *testing.T) {
	facts := make([]approvalview.Fact, 20)
	for index := range facts {
		facts[index] = approvalview.Fact{Label: "Detail", Value: strings.Repeat("&", 500)}
	}
	approval := Approval{Broker: "GitHub", Requester: "agent", Operation: "repo.delete", Reason: strings.Repeat("&", 2_000),
		Presentation: approvalview.Presentation{Risk: approvalview.RiskHigh, Title: "Delete", Target: "example/repo", Facts: facts}}
	snapshot := SnapshotJSON(approval)
	if len(snapshot) > 64*1024 || strings.Contains(snapshot, `\u0026`) {
		t.Fatalf("SnapshotJSON() length=%d contains escaped HTML=%v", len(snapshot), strings.Contains(snapshot, `\u0026`))
	}

	projected := Project(t.Context(), "GitHub", nil, grants.Grant{Client: strings.Repeat("a", 200)}, "token")
	if len(projected.Requester) > 80 || !strings.HasSuffix(projected.Requester, "…") {
		t.Fatalf("Project() requester = %q (%d bytes)", projected.Requester, len(projected.Requester))
	}
}
