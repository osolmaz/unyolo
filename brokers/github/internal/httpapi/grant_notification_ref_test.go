package httpapi

import (
	"testing"

	"github.com/osolmaz/unyolo/approval/notifier"
)

func TestShouldSupersedeNotification(t *testing.T) {
	sent := notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 7, Text: "approval"}
	different := notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 8, Text: "approval"}
	if !shouldSupersedeNotification(nil, sent) {
		t.Fatal("nil stored notification was not superseded")
	}
	if !shouldSupersedeNotification(&different, sent) {
		t.Fatal("different stored notification was not superseded")
	}
	if shouldSupersedeNotification(&sent, sent) {
		t.Fatal("identical callback-owned notification was superseded")
	}
}
