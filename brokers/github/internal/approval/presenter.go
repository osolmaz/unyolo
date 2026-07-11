// Package approval renders GitHub-specific operator approval details.
package approval

import (
	"context"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

// Presenter projects canonical GitHub grants into bounded display fields.
type Presenter struct{}

func (Presenter) Present(_ context.Context, grant grants.Grant) (operatorinbox.Presentation, error) {
	target := targetSummary(grant)
	if target == "" {
		return operatorinbox.Presentation{}, fmt.Errorf("GitHub grant %q has no target", grant.ID)
	}
	fields := []operatorinbox.DisplayField{{Label: "Operation", Value: grant.Operation}}
	labels := map[string]string{"ref": "Ref", "base_ref": "Base ref", "head_ref": "Head ref", "path": "Path"}
	for _, key := range []string{"ref", "base_ref", "head_ref", "path"} {
		if value := policy.FirstValue(grant.Attrs[key]); value != "" {
			fields = append(fields, operatorinbox.DisplayField{Label: labels[key], Value: value})
		}
	}
	return operatorinbox.Presentation{
		Risk: risk(grant.Operation), Title: "GitHub: " + grant.Operation,
		Summary: "Review this GitHub operation before granting temporary access.",
		Target:  target, Fields: fields,
	}, nil
}

func targetSummary(grant grants.Grant) string {
	if grant.Target.Kind != "repo" {
		return grant.Target.Kind
	}
	owner := policy.FirstValue(grant.Target.Fields["owner"])
	name := policy.FirstValue(grant.Target.Fields["name"])
	if owner == "" || name == "" {
		return ""
	}
	return owner + "/" + name
}

func risk(operation string) operatorinbox.Risk {
	switch {
	case strings.Contains(operation, "force"), strings.Contains(operation, "delete"), strings.Contains(operation, "merge"):
		return operatorinbox.RiskCritical
	case strings.Contains(operation, "push"), strings.Contains(operation, "create"), strings.Contains(operation, "update"):
		return operatorinbox.RiskHigh
	case strings.Contains(operation, "read"), strings.Contains(operation, "fetch"), strings.Contains(operation, "list"):
		return operatorinbox.RiskLow
	default:
		return operatorinbox.RiskMedium
	}
}
