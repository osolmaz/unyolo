package notify

import (
	"context"
	"testing"
)

func TestMemoryNotifier(t *testing.T) {
	notifier := &Memory{}
	ref, err := notifier.SendApproval(context.Background(), ApprovalMessage{
		GrantID:       "grant-1",
		DecisionToken: "token",
		Client:        "bob",
		Operation:     "session.shell",
	})
	if err != nil || ref.Kind != "memory" || ref.MessageID != 1 {
		t.Fatalf("SendApproval() = %+v err=%v", ref, err)
	}
	if err := notifier.UpdateStatus(context.Background(), ref, "approved"); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	if len(notifier.Messages) != 1 || notifier.Statuses[0] != "approved" {
		t.Fatalf("memory notifier = %+v", notifier)
	}
	if notifier.Messages[0].DecisionToken != "" {
		t.Fatalf("memory notifier retained decision token: %+v", notifier.Messages[0])
	}
}
