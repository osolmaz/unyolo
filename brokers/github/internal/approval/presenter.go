// Package approval renders GitHub-specific operator approval details.
package approval

import (
	"context"
	"fmt"
	"strings"

	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

// Presenter projects canonical GitHub grants into bounded display fields.
type Presenter struct{}

func (Presenter) Present(_ context.Context, grant grants.Grant) (operatorinbox.Presentation, error) {
	target := TargetSummary(grant.Target)
	if target == "" {
		return operatorinbox.Presentation{}, fmt.Errorf("GitHub grant %q has no target", grant.ID)
	}
	return operatorinbox.Presentation{
		Risk: risk(grant.Operation), Title: "GitHub: " + grant.Operation,
		Summary: "Review this GitHub operation before granting temporary access.",
		Target:  target, Fields: DisplayFields(grant),
	}, nil
}

// TargetSummary renders the complete canonical target without exposing request payloads.
func TargetSummary(target policy.Target) string {
	kind := strings.TrimSpace(target.Kind)
	owner := policy.FirstValue(target.Fields["owner"])
	name := policy.FirstValue(target.Fields["name"])
	if kind == "repo" {
		return repositoryTarget(owner, name)
	}
	locator := targetLocator(target, owner, name)
	if kind == "" || locator == "" {
		return ""
	}
	return kind + " " + locator
}

func repositoryTarget(owner, name string) string {
	if owner == "" || name == "" {
		return ""
	}
	return owner + "/" + name
}

func targetLocator(target policy.Target, owner, name string) string {
	locator := name
	if owner != "" && name != "" {
		locator = repositoryTarget(owner, name)
	} else if locator == "" {
		locator = owner
	}
	if number := policy.FirstValue(target.Fields["number"]); number != "" {
		locator = strings.TrimSpace(locator + " #" + number)
	} else if id := policy.FirstValue(target.Fields["id"]); id != "" {
		locator = strings.TrimSpace(locator + " " + id)
	} else if nodeID := policy.FirstValue(target.Fields["node_id"]); nodeID != "" {
		locator = strings.TrimSpace(locator + " " + nodeID)
	}
	return locator
}

// DisplayFields returns the exact target and closed policy vocabulary used by every approval surface.
func DisplayFields(grant grants.Grant) []operatorinbox.DisplayField {
	fields := []operatorinbox.DisplayField{{Label: "Operation", Value: grant.Operation}, {Label: "Target", Value: TargetSummary(grant.Target)}}
	targetLabels := map[string]string{"owner": "Target owner", "name": "Target name", "number": "Target number", "id": "Target ID", "node_id": "Target node ID"}
	for _, key := range []string{"owner", "name", "number", "id", "node_id"} {
		if values := grant.Target.Fields[key]; len(values) > 0 {
			fields = append(fields, operatorinbox.DisplayField{Label: targetLabels[key], Value: strings.Join(values, ", ")})
		}
	}
	attributeLabels := map[string]string{ // #nosec G101 -- keys name non-secret policy metadata shown to the operator.
		"actor_id": "Actor ID", "actor_login": "Actor", "base_ref": "Base ref", "credential_kind": "Credential kind",
		"credential_slot": "Credential slot", "environment": "Environment", "head_ref": "Head ref", "label": "Labels",
		"merge_method": "Merge method", "path": "Path", "permission": "Permission", "ref": "Ref", "release_state": "Release state",
		"resource_id": "Resource ID", "role": "Role", "visibility": "Visibility", "workflow": "Workflow", "workflow_ref": "Workflow ref",
	}
	for _, key := range []string{"actor_id", "actor_login", "base_ref", "credential_kind", "credential_slot", "environment", "head_ref",
		"label", "merge_method", "path", "permission", "ref", "release_state", "resource_id", "role", "visibility", "workflow", "workflow_ref"} {
		if values := grant.Attrs[key]; len(values) > 0 {
			fields = append(fields, operatorinbox.DisplayField{Label: attributeLabels[key], Value: strings.Join(values, ", ")})
		}
	}
	return fields
}

func risk(operation string) operatorinbox.Risk {
	if descriptor, found := opcatalog.ByName(operation); found {
		return operatorinbox.Risk(descriptor.Risk)
	}
	risks := map[string]operatorinbox.Risk{
		"git.fetch":              operatorinbox.RiskLow,
		"git.push.advertise":     operatorinbox.RiskMedium,
		"git.push.branch_create": operatorinbox.RiskHigh,
		"git.push.fast_forward":  operatorinbox.RiskHigh,
		"git.push.force":         operatorinbox.RiskCritical,
		"git.ref.delete":         operatorinbox.RiskCritical,
		"git.tag.update":         operatorinbox.RiskHigh,
		"webhook.github.receive": operatorinbox.RiskMedium,
	}
	if value, ok := risks[operation]; ok {
		return value
	}
	return operatorinbox.RiskUnknown
}
