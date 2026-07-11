// Package presenter renders bounded sudo command approval details.
package presenter

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/catalog"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/sudopolicy"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	corepolicy "github.com/osolmaz/brokerkit/policy"
)

type Presenter struct{ Catalog *catalog.Snapshot }

func (p Presenter) Present(_ context.Context, grant grants.Grant) (operatorinbox.Presentation, error) {
	commandID := corepolicy.FirstValue(grant.Attrs[sudopolicy.AttrCommandID])
	command, ok := p.Catalog.Command(commandID)
	if !ok {
		return operatorinbox.Presentation{}, fmt.Errorf("sudo command %q is unavailable", commandID)
	}
	target := corepolicy.FirstValue(grant.Target.Fields[sudopolicy.TargetName])
	if target == "" {
		return operatorinbox.Presentation{}, errorsNewTarget()
	}
	fields := []operatorinbox.DisplayField{
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
			fields = append(fields, operatorinbox.DisplayField{Label: "Argument " + argument.Slot, Value: value})
		}
	}
	argumentSummary := "Arguments are fixed by the catalog."
	if len(fields) > 4 {
		argumentSummary = "Arguments are fixed or bounded by the catalog."
	}
	summary := fmt.Sprintf("Run %s once as %s. %s", command.ID, target, argumentSummary)
	if command.Description != "" {
		summary = command.Description + " " + summary
	}
	return operatorinbox.Presentation{
		Risk: risk(command.Risk), Title: "Run privileged command", Summary: summary,
		Target: target, Fields: fields,
	}, nil
}

func risk(value string) operatorinbox.Risk {
	switch strings.ToLower(value) {
	case "low":
		return operatorinbox.RiskLow
	case "medium":
		return operatorinbox.RiskMedium
	case "high":
		return operatorinbox.RiskHigh
	default:
		return operatorinbox.RiskUnknown
	}
}

func errorsNewTarget() error { return fmt.Errorf("sudo grant target is unavailable") }
