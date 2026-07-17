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
	if p.Catalog == nil {
		return approvalview.Presentation{}, fmt.Errorf("sudo command %q is unavailable", commandID)
	}
	command, ok := p.Catalog.Command(commandID)
	if !ok {
		return approvalview.Presentation{}, fmt.Errorf("sudo command %q is unavailable", commandID)
	}
	target := corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName])
	if target == "" {
		return approvalview.Presentation{}, errorsNewTarget()
	}
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
		if value := corepolicy.FirstValue(grant.Attrs[sudopolicy.ArgumentPrefix+argument.Slot]); value != "" {
			facts = append(facts, approvalview.Fact{Label: "Argument " + argument.Slot, Value: value})
		}
	}
	argumentSummary := "Arguments are fixed by the catalog."
	if len(facts) > 4 {
		argumentSummary = "Arguments are fixed or bounded by the catalog."
	}
	summary := fmt.Sprintf("Run %s once as %s. %s", command.ID, target, argumentSummary)
	if command.Description != "" {
		summary = command.Description + " " + summary
	}
	presentationRisk := risk(command.Risk)
	return approvalview.Presentation{
		Risk: risk(command.Risk), Title: "Run privileged command", Summary: summary,
		Target: target, Facts: facts,
		Warnings: []approvalview.Warning{{Severity: presentationRisk, Text: "This command runs with another user's privileges on the host. Review the target user and bounded arguments carefully."}},
	}, nil
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
