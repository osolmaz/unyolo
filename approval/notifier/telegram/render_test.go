package telegram

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/budget"
)

func TestRenderApprovalCanonicalLayout(t *testing.T) {
	got, err := RenderApproval(validApproval())
	if err != nil {
		t.Fatal(err)
	}
	want := `🔐 <b>Approval needed for GitHub</b>

👤 <b>Requester:</b> agent-a
⚙️ <b>Operation:</b> repo.delete
🔑 <b>Grant mode:</b> execution (exact, single-use)
📍 <b>Target:</b> example/project
🛡️ <b>Risk:</b> critical

<b>Delete repository</b>
Permanently delete the selected repository.

<b>Details</b>
• <b>Visibility:</b> private

📝 <b>Reason:</b> remove an obsolete test repository
⏱️ <b>Access:</b> 5 minutes
🔁 <b>Uses:</b> 1
⌛ <b>Request expires:</b> 2026-07-17 10:00 UTC

⚠️ <b>Critical warning:</b> This operation permanently deletes the repository.`
	if got != want {
		t.Fatalf("RenderApproval() mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderApprovalDistinguishesReusableWindowMode(t *testing.T) {
	approval := validApproval()
	approval.Mode = "window"
	approval.MaxUses = 25
	text, err := RenderApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Grant mode:</b> window (reusable)") || !strings.Contains(text, "Uses:</b> 25") {
		t.Fatalf("window approval text = %q", text)
	}
}

func TestRenderApprovalProviderFixturesShareLayout(t *testing.T) {
	tests := []struct {
		broker, operation, title, target string
	}{
		{"Hugging Face", "repo.delete", "Delete repository", "dataset:example/data"},
		{"GitHub", "repository.archive", "Archive repository", "example/project"},
		{"sudo", "command.run", "Restart service", "deploy@example-host"},
	}
	for _, test := range tests {
		t.Run(test.broker, func(t *testing.T) {
			approval := validApproval()
			approval.Broker, approval.Operation = test.broker, test.operation
			approval.Presentation.Title, approval.Presentation.Target = test.title, test.target
			text, err := RenderApproval(approval)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range []string{
				"🔐 <b>Approval needed for " + test.broker + "</b>",
				"⚙️ <b>Operation:</b> " + test.operation,
				"📍 <b>Target:</b> " + test.target,
				"<b>" + test.title + "</b>",
			} {
				if !strings.Contains(text, line) {
					t.Fatalf("rendered fixture missing %q:\n%s", line, text)
				}
			}
		})
	}
}

func TestRenderStatusCoversLifecycle(t *testing.T) {
	tests := []notify.Status{
		{Kind: notify.StatusActive}, {Kind: notify.StatusDenied}, {Kind: notify.StatusPendingExpired},
		{Kind: notify.StatusActiveExpired}, {Kind: notify.StatusConsumed}, {Kind: notify.StatusRevoked},
		{Kind: notify.StatusCanceled}, {Kind: notify.StatusRetained},
		{Kind: notify.StatusUsedActive, UsedCount: 2, MaxUses: usebudget.Limit(5)},
		{Kind: notify.StatusUsedActive, UsedCount: 2, MaxUses: usebudget.Unlimited},
		{Kind: notify.StatusSuperseded}, {Kind: notify.StatusUnavailable}, {Kind: notify.StatusClosed},
	}
	seen := map[string]bool{}
	for _, status := range tests {
		text := renderStatus(status)
		if text == "" || seen[text] {
			t.Fatalf("renderStatus(%+v) = %q", status, text)
		}
		seen[text] = true
		terminal := withDecisionStatus("pending", status)
		if !strings.Contains(terminal, "<b>Status</b>") || strings.Count(terminal, "<b>Status</b>") != 1 {
			t.Fatalf("terminal status = %q", terminal)
		}
		if repeated := withDecisionStatus(terminal, status); repeated != terminal {
			t.Fatalf("terminal rendering is not idempotent: %q", repeated)
		}
	}
}

func TestRenderApprovalEscapesMarkupAndReservesTerminalSpace(t *testing.T) {
	approval := validApproval()
	approval.Broker = `<b onclick="x">broker</b>`
	approval.Requester = `<script>alert(1)</script>`
	approval.Operation = strings.Repeat("x", 500)
	approval.Reason = strings.Repeat("<&", 666)
	approval.Presentation.Summary = strings.Repeat("界", 666)
	approval.Presentation.Facts = make([]approvalview.Fact, 20)
	for index := range approval.Presentation.Facts {
		approval.Presentation.Facts[index] = approvalview.Fact{Label: "Detail", Value: strings.Repeat("&", 500)}
	}
	first, err := RenderApproval(approval)
	if err != nil {
		t.Fatal(err)
	}
	second, err := RenderApproval(approval)
	if err != nil || second != first {
		t.Fatalf("rendering is not deterministic: err=%v", err)
	}
	if strings.Contains(first, `<script>`) || strings.Contains(first, `<b onclick=`) || !strings.Contains(first, "&lt;script&gt;") {
		t.Fatalf("dynamic markup was not escaped: %s", first)
	}
	if visibleLength(first) > maxTelegramText-terminalReserve || visibleLength(withDecisionStatus(first, notify.Status{Kind: notify.StatusRetained})) > maxTelegramText {
		t.Fatalf("rendered message lengths pending=%d terminal=%d", visibleLength(first), visibleLength(withDecisionStatus(first, notify.Status{Kind: notify.StatusRetained})))
	}
	if len(first) > 32*1024 {
		t.Fatalf("raw rendered message length = %d", len(first))
	}
	if !strings.Contains(first, "…") || !utf8.ValidString(first) {
		t.Fatalf("bounded rendering did not truncate safely: %q", first)
	}
}

func TestRenderApprovalRejectsInvalidSemanticEnvelope(t *testing.T) {
	approval := validApproval()
	approval.Reason = "bad\x00reason"
	if _, err := RenderApproval(approval); err == nil {
		t.Fatal("RenderApproval() accepted a control character")
	}
	approval = validApproval()
	approval.Presentation.Warnings = []approvalview.Warning{{Severity: "invalid", Text: "warning"}}
	if _, err := RenderApproval(approval); err == nil {
		t.Fatal("RenderApproval() accepted an invalid warning")
	}
}

func TestRenderLimitsExhaustDeterministicReductionOrder(t *testing.T) {
	limits := renderLimits{facts: 1, warnings: 2, broker: 41, requester: 41, operation: 81, target: 81, title: 81,
		summary: 600, reason: 121, warning: 101, includeSummary: true}
	steps := 0
	for limits.shrink() {
		steps++
	}
	if steps != 10 || limits.facts != 0 || limits.warnings != 1 || limits.includeSummary ||
		limits.reason != 120 || limits.target != 80 || limits.title != 80 || limits.operation != 80 ||
		limits.warning != 100 || limits.requester != 40 || limits.broker != 40 {
		t.Fatalf("exhausted limits = %+v after %d steps", limits, steps)
	}
}
