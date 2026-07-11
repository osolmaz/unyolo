package httpapi

import (
	"testing"

	"github.com/osolmaz/brokerkit/notify"
)

func TestShouldSupersedeNotifier(t *testing.T) {
	sent := notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 7, Text: "grant text"}
	different := notify.MessageRef{Kind: "telegram", ChatID: 1, MessageID: 8, Text: "grant text"}
	stored := notify.MessageRef(sent)
	if !shouldSupersedeNotifier(nil, sent) {
		t.Fatal("shouldSupersedeNotifier(nil) = false")
	}
	if !shouldSupersedeNotifier(&different, sent) {
		t.Fatal("shouldSupersedeNotifier(different) = false")
	}
	if shouldSupersedeNotifier(&stored, sent) {
		t.Fatal("shouldSupersedeNotifier(same) = true")
	}
}
