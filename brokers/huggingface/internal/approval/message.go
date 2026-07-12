// Package approval renders Hugging Face-specific operator approval messages.
package approval

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var operationTexts = map[string]string{
	"repo.create":          "create a Hugging Face repository",
	"repo.contents.read":   "read repo contents",
	"git.fetch":            "fetch from a Git repo",
	"git.push.append":      "append-push to a Git repo",
	"git.push.force":       "force-push / rewrite Git history",
	"git.ref.delete":       "delete a Git ref",
	"git.tag.update":       "move or delete a Git tag",
	"bucket.object.read":   "read a bucket object",
	"bucket.object.write":  "write a bucket object",
	"bucket.object.delete": "delete a bucket object",
}

// Message contains the HF fields shown to an operator.
type Message struct {
	Client           string
	Operation        string
	Mode             string
	Target           string
	Ref              string
	Attrs            map[string]any
	Reason           string
	RequestedMinutes int
	MaxUses          int
	PendingExpiresAt time.Time
}

// Text renders an HF-specific approval summary for a shared notifier.
func Text(msg Message) string {
	return fmt.Sprintf("🔐 Approval needed for hf-broker\n\n%s is asking to %s.\n\n%s\n\n📝 Reason: %s\n\n⚠️ Approve only if this looks right.",
		msg.Client,
		operationText(msg.Operation),
		strings.Join(detailLines(msg), "\n"),
		msg.Reason,
	)
}

func detailLines(msg Message) []string {
	lines := []string{fmt.Sprintf("📍 Target: %s", msg.Target)}
	if msg.Ref != "" {
		lines = append(lines, fmt.Sprintf("🌿 Ref: %s", msg.Ref))
	}
	if msg.Mode != "" {
		lines = append(lines, fmt.Sprintf("⚙️ Mode: %s", msg.Mode))
	}
	if attrs := attrsText(msg.Attrs); attrs != "" {
		lines = append(lines, fmt.Sprintf("🏷️ Attrs: %s", attrs))
	}
	return append(lines,
		fmt.Sprintf("⏱️ Access: %d minutes", msg.RequestedMinutes),
		fmt.Sprintf("🔁 Uses: %s", usesText(msg.Operation, msg.MaxUses)),
		fmt.Sprintf("⌛ Request expires: %s", msg.PendingExpiresAt.UTC().Format("2006-01-02 15:04 UTC")),
	)
}

func attrsText(attrs map[string]any) string {
	if len(attrs) == 0 {
		return ""
	}
	data, err := json.Marshal(attrs)
	if err != nil {
		return "present"
	}
	return string(data)
}

func usesText(operation string, maxUses int) string {
	noun := "use"
	if strings.HasPrefix(operation, "git.push.") {
		noun = "push"
	}
	if maxUses <= 1 {
		return "1 " + noun
	}
	if noun == "push" {
		noun = "pushes"
	} else {
		noun += "s"
	}
	return fmt.Sprintf("up to %d %s", maxUses, noun)
}

func operationText(operation string) string {
	if text, ok := operationTexts[operation]; ok {
		return text
	}
	return operation
}
