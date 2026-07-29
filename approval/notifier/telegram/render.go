package telegram

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/osolmaz/unyolo/approval/notification"
	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/budget"
)

const (
	rendererID       = "telegram-html-v1"
	maxTelegramText  = 4096
	terminalReserve  = 192
	maxRenderedFacts = 6
)

type renderLimits struct {
	facts, warnings                             int
	broker, requester, operation, target, title int
	summary, reason, warning                    int
	includeSummary                              bool
}

// RenderApproval renders one semantic approval using unYOLO's canonical Telegram layout.
func RenderApproval(approval approvalnotify.Approval) (string, error) {
	if err := validateApproval(approval); err != nil {
		return "", err
	}
	limits := renderLimits{
		facts: min(len(approval.Presentation.Facts), maxRenderedFacts), warnings: min(len(approval.Presentation.Warnings), 2),
		broker: 100, requester: 80, operation: 180, target: 240, title: 180,
		summary: 600, reason: 700, warning: 240, includeSummary: approval.Presentation.Summary != "",
	}
	for {
		text := renderPending(approval, limits)
		if visibleLength(text) <= maxTelegramText-terminalReserve {
			return text, nil
		}
		if !limits.shrink() {
			return "", errors.New("approval exceeds Telegram message limit")
		}
	}
}

func (limits *renderLimits) shrink() bool {
	steps := []func() bool{
		func() bool { return decrement(&limits.facts, 0) },
		func() bool { return disable(&limits.includeSummary) },
		func() bool { return decrement(&limits.warnings, 1) },
		func() bool { return reduceLimit(&limits.reason, 700, 120) },
		func() bool { return reduceLimit(&limits.target, 240, 80) },
		func() bool { return reduceLimit(&limits.title, 180, 80) },
		func() bool { return reduceLimit(&limits.operation, 180, 80) },
		func() bool { return reduceLimit(&limits.warning, 240, 100) },
		func() bool { return reduceLimit(&limits.requester, 80, 40) },
		func() bool { return reduceLimit(&limits.broker, 100, 40) },
	}
	for _, step := range steps {
		if step() {
			return true
		}
	}
	return false
}

func decrement(value *int, minimum int) bool {
	if *value <= minimum {
		return false
	}
	*value--
	return true
}

func disable(value *bool) bool {
	if !*value {
		return false
	}
	*value = false
	return true
}

func reduceLimit(value *int, step, minimum int) bool {
	if *value <= minimum {
		return false
	}
	*value = max(minimum, *value-step/4)
	return true
}

func validateApproval(approval approvalnotify.Approval) error {
	if !safeLine(approval.Broker, 200, true) || !safeLine(approval.Requester, 80, true) || !safeLine(approval.Operation, 500, true) {
		return errors.New("approval identity is invalid")
	}
	if approval.Mode != "window" && approval.Mode != "execution" {
		return errors.New("approval mode is invalid")
	}
	if !safeText(approval.Reason, 2_000) || approval.RequestedDurationSeconds <= 0 || approval.PendingExpiresAt.IsZero() {
		return errors.New("approval bounds are invalid")
	}
	return approvalview.Validate(approval.Presentation)
}

func renderPending(approval approvalnotify.Approval, limits renderLimits) string {
	var sections []string
	sections = append(sections, "🔐 <b>Approval needed for "+escaped(approval.Broker, limits.broker)+"</b>")
	sections = append(sections, strings.Join([]string{
		"👤 <b>Requester:</b> " + escaped(approval.Requester, limits.requester),
		"⚙️ <b>Operation:</b> " + escaped(approval.Operation, limits.operation),
		"🔑 <b>Grant mode:</b> " + approvalModeText(approval.Mode),
		"📍 <b>Target:</b> " + escaped(approval.Presentation.Target, limits.target),
		"🛡️ <b>Risk:</b> " + escaped(string(approval.Presentation.Risk), 20),
	}, "\n"))

	title := "<b>" + escaped(approval.Presentation.Title, limits.title) + "</b>"
	if limits.includeSummary {
		title += "\n" + escaped(approval.Presentation.Summary, limits.summary)
	}
	sections = append(sections, title)

	if details := renderDetails(approval, limits.facts); details != "" {
		sections = append(sections, details)
	}

	sections = append(sections, renderAccess(approval, limits.reason))

	if warnings := renderWarnings(approval.Presentation.Warnings, limits.warnings, limits.warning); warnings != "" {
		sections = append(sections, warnings)
	}
	if approval.PresentationUnavailable {
		sections = append(sections, "⚠️ <b>Presentation unavailable:</b> Review the canonical request in the operator inbox before deciding.")
	}
	return strings.Join(sections, "\n\n")
}

func renderDetails(approval approvalnotify.Approval, factCount int) string {
	if factCount == 0 && approval.Presentation.PlanHash == "" {
		return ""
	}
	lines := []string{"<b>Details</b>"}
	for _, fact := range approval.Presentation.Facts[:factCount] {
		lines = append(lines, "• <b>"+escaped(fact.Label, 60)+":</b> "+escaped(fact.Value, 220))
	}
	if approval.Presentation.PlanHash != "" && !hasPlanHashFact(approval.Presentation.Facts[:factCount]) {
		lines = append(lines, "• <b>Plan digest:</b> "+escaped(approval.Presentation.PlanHash, 128))
	}
	if factCount < len(approval.Presentation.Facts) {
		lines = append(lines, "• <i>Additional bounded details are available in the operator inbox.</i>")
	}
	return strings.Join(lines, "\n")
}

func renderAccess(approval approvalnotify.Approval, reasonLimit int) string {
	return strings.Join([]string{
		"📝 <b>Reason:</b> " + escaped(approval.Reason, reasonLimit),
		"⏱️ <b>Access:</b> " + durationText(approval.RequestedDurationSeconds),
		"🔁 <b>Uses:</b> " + usesText(approval.MaxUses),
		"⌛ <b>Request expires:</b> " + approval.PendingExpiresAt.UTC().Format("2006-01-02 15:04 UTC"),
	}, "\n")
}

func approvalModeText(mode string) string {
	if mode == "execution" {
		return "execution (exact, single-use)"
	}
	return "window (reusable)"
}

func renderWarnings(warnings []approvalview.Warning, count, textLimit int) string {
	lines := make([]string, 0, count)
	for _, warning := range warnings[:count] {
		label := "Warning"
		if warning.Severity == approvalview.RiskCritical {
			label = "Critical warning"
		}
		lines = append(lines, riskEmoji(warning.Severity)+" <b>"+label+":</b> "+escaped(warning.Text, textLimit))
	}
	return strings.Join(lines, "\n")
}

func visibleLength(text string) int {
	withoutMarkup := strings.NewReplacer("<b>", "", "</b>", "", "<i>", "", "</i>", "").Replace(text)
	return utf8.RuneCountInString(html.UnescapeString(withoutMarkup))
}

func hasPlanHashFact(facts []approvalview.Fact) bool {
	for _, fact := range facts {
		if strings.EqualFold(fact.Label, "plan digest") || strings.EqualFold(fact.Label, "plan hash") {
			return true
		}
	}
	return false
}

func durationText(seconds int64) string {
	duration := time.Duration(seconds) * time.Second
	if duration%time.Hour == 0 {
		return strconv.FormatInt(int64(duration/time.Hour), 10) + plural(duration/time.Hour, " hour", " hours")
	}
	if duration%time.Minute == 0 {
		return strconv.FormatInt(int64(duration/time.Minute), 10) + plural(duration/time.Minute, " minute", " minutes")
	}
	return strconv.FormatInt(seconds, 10) + plural(time.Duration(seconds), " second", " seconds")
}

func plural(value time.Duration, singular, multiple string) string {
	if value == 1 {
		return singular
	}
	return multiple
}

func usesText(limit usebudget.Limit) string {
	if limit.IsUnlimited() {
		return "unlimited until expiry"
	}
	return strconv.Itoa(int(limit))
}

func riskEmoji(risk approvalview.Risk) string {
	if risk == approvalview.RiskCritical || risk == approvalview.RiskHigh {
		return "⚠️"
	}
	return "ℹ️"
}

func escaped(value string, maximum int) string {
	return html.EscapeString(truncate(value, maximum))
}

func truncate(value string, maximum int) string {
	runes := []rune(value)
	if len(runes) <= maximum {
		return value
	}
	if maximum <= 1 {
		return "…"
	}
	return string(runes[:maximum-1]) + "…"
}

func safeLine(value string, maximum int, required bool) bool {
	if !safeText(value, maximum) || (required && strings.TrimSpace(value) == "") {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func safeText(value string, maximum int) bool {
	if !utf8.ValidString(value) || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) && char != '\n' && char != '\t' {
			return false
		}
	}
	return true
}

func renderedDigest(text string) string {
	digest := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(digest[:])
}

var terminalStatusText = map[notify.StatusKind]string{
	notify.StatusActive:         "✅ Approved. Access is active.",
	notify.StatusDenied:         "❌ Denied. Access was not granted.",
	notify.StatusPendingExpired: "⌛ Expired. The request was not approved in time.",
	notify.StatusActiveExpired:  "⌛ Expired. Access is closed.",
	notify.StatusConsumed:       "✅ Used. Access is now closed.",
	notify.StatusRevoked:        "🚫 Revoked. Access is closed.",
	notify.StatusCanceled:       "🚫 Canceled. The approval request is closed.",
	notify.StatusRetained:       "⚠️ Result is ambiguous. Access is closed pending operator review.",
	notify.StatusSuperseded:     "⚠️ Superseded. Use the latest approval message.",
	notify.StatusUnavailable:    "⚠️ Unavailable. The approval request no longer exists.",
}

func renderStatus(status notify.Status) string {
	if status.Kind == notify.StatusUsedActive {
		remaining, finite := status.MaxUses.Remaining(status.UsedCount, status.ReservedCount)
		if !finite {
			return "✅ Used. Access remains active until expiry."
		}
		return fmt.Sprintf("✅ Used %d time(s). %d use(s) remain.", status.UsedCount, remaining)
	}
	if text := terminalStatusText[status.Kind]; text != "" {
		return text
	}
	return "🚫 Closed. The approval request is no longer pending."
}

func answerText(answer notify.Answer) string {
	values := map[notify.Answer]string{
		notify.AnswerApproved: "Grant approved", notify.AnswerDenied: "Grant denied",
		notify.AnswerAlreadyApproved: "Grant already approved", notify.AnswerAlreadyDenied: "Grant already denied",
		notify.AnswerAlreadyExpired: "Grant already expired", notify.AnswerAlreadyConsumed: "Grant already used",
		notify.AnswerAlreadyRevoked: "Grant already revoked", notify.AnswerAlreadyCanceled: "Grant already canceled",
		notify.AnswerNotFound: "Grant not found", notify.AnswerSuperseded: "Approval request was superseded",
		notify.AnswerIgnored: "Grant decision ignored", notify.AnswerRouteUnavailable: "Approval route is unavailable",
		notify.AnswerUnavailable: "Broker temporarily unavailable; try again", notify.AnswerClosed: "Grant is no longer pending",
	}
	if value := values[answer]; value != "" {
		return value
	}
	return values[notify.AnswerIgnored]
}
