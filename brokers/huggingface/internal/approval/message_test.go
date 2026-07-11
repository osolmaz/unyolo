package approval

import (
	"strings"
	"testing"
	"time"
)

func TestTextRendersForcePushDetailsWithoutDecisionToken(t *testing.T) {
	text := Text(forcePushMessage())
	for _, want := range []string{
		"🔐 Approval needed for hf-broker",
		"agent is asking to force-push / rewrite Git history.",
		"⚙️ Mode: window",
		`🏷️ Attrs: {"ref_change":"non_fast_forward"}`,
		"⏱️ Access: 15 minutes",
		"🔁 Uses: up to 3 pushes",
		"⌛ Request expires: 2026-07-06 01:02 UTC",
		"⚠️ Approve only if this looks right.",
		"dataset/acme/repo",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Text() missing %q in %q", want, text)
		}
	}
}

func TestTextShowsNonPushUses(t *testing.T) {
	text := Text(Message{
		Client:           "agent",
		Operation:        "repo.contents.read",
		Mode:             "window",
		Target:           "dataset/acme/repo",
		Attrs:            map[string]any{"max_bytes": int64(12)},
		Reason:           "inspect one file",
		RequestedMinutes: 5,
		MaxUses:          1,
		PendingExpiresAt: time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC),
	})
	for _, want := range []string{
		"agent is asking to read repo contents.",
		"⚙️ Mode: window",
		`🏷️ Attrs: {"max_bytes":12}`,
		"🔁 Uses: 1 use",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Text() missing %q in %q", want, text)
		}
	}
	if strings.Contains(text, "push") || strings.Contains(text, "🌿 Ref:") {
		t.Fatalf("Text() has push/ref wording for non-push grant: %q", text)
	}
}

func TestTextHandlesUnknownOperationAndUnencodableAttrs(t *testing.T) {
	msg := forcePushMessage()
	msg.Operation = "custom.operation"
	msg.Attrs = map[string]any{"bad": func() {}}
	text := Text(msg)
	if !strings.Contains(text, "custom.operation") || !strings.Contains(text, "Attrs: present") {
		t.Fatalf("Text() = %q", text)
	}
}

func forcePushMessage() Message {
	return Message{
		Client:           "agent",
		Operation:        "git.push.force",
		Mode:             "window",
		Target:           "dataset/acme/repo",
		Ref:              "refs/heads/main",
		Attrs:            map[string]any{"ref_change": "non_fast_forward"},
		Reason:           "recover",
		RequestedMinutes: 15,
		MaxUses:          3,
		PendingExpiresAt: time.Date(2026, 7, 6, 1, 2, 3, 0, time.UTC),
	}
}
