// Package presenter renders bounded sudo command approval details.
package presenter

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

type Presenter struct{ Catalog *catalog.Snapshot }

func (p Presenter) Present(_ context.Context, grant grants.Grant) (approvalview.Presentation, error) {
	commandID := corepolicy.FirstValue(grant.Attrs[sudopolicy.AttrCommandID])
	command, err := resolveCommand(p.Catalog, commandID)
	if err != nil {
		return approvalview.Presentation{}, err
	}
	target := corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName])
	if target == "" {
		return approvalview.Presentation{}, errorsNewTarget()
	}
	facts := commandFacts(command, target, grant.Attrs)
	presentationRisk := risk(command.Risk)
	return approvalview.Presentation{
		Risk: presentationRisk, Title: "Run privileged command", Summary: commandSummary(command, target, len(facts) > 4),
		Target: target, Facts: facts,
		Warnings: []approvalview.Warning{{Severity: presentationRisk, Text: "This command runs with another user's privileges on the host. Review the target user and bounded arguments carefully."}},
	}, nil
}

func resolveCommand(snapshot *catalog.Snapshot, commandID string) (catalog.Command, error) {
	if snapshot == nil {
		return catalog.Command{}, fmt.Errorf("sudo command %q is unavailable", commandID)
	}
	command, ok := snapshot.Command(commandID)
	if !ok {
		return catalog.Command{}, fmt.Errorf("sudo command %q is unavailable", commandID)
	}
	return command, nil
}

func commandFacts(command catalog.Command, target string, attrs map[string][]string) []approvalview.Fact {
	facts := []approvalview.Fact{
		{Label: "Command", Value: command.ID},
		{Label: "Target user", Value: target},
		{Label: "Working directory", Value: command.WorkingDirectory},
		{Label: "Timeout", Value: strconv.Itoa(command.TimeoutSeconds) + " seconds"},
	}
	for _, argument := range command.Arguments {
		if argument.Slot == "" {
			continue
		}
		if value := corepolicy.FirstValue(attrs[sudopolicy.ArgumentPrefix+argument.Slot]); value != "" {
			facts = append(facts, approvalview.Fact{Label: "Argument " + argument.Slot, Value: value})
		}
	}
	return facts
}

func commandSummary(command catalog.Command, target string, bounded bool) string {
	argumentSummary := "Arguments are fixed by the catalog."
	if bounded {
		argumentSummary = "Arguments are fixed or bounded by the catalog."
	}
	summary := fmt.Sprintf("Run %s once as %s. %s", command.ID, target, argumentSummary)
	if command.Description != "" {
		summary = command.Description + " " + summary
	}
	return summary
}

func risk(value string) approvalview.Risk {
	switch strings.ToLower(value) {
	case "low":
		return approvalview.RiskLow
	case "medium":
		return approvalview.RiskMedium
	case "high":
		return approvalview.RiskHigh
	default:
		return approvalview.RiskUnknown
	}
}

func errorsNewTarget() error { return fmt.Errorf("sudo grant target is unavailable") }
