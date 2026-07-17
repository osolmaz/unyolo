// Package approval renders GitHub-specific operator approval details.
package approval

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/osolmaz/brokerkit/approvalview"
	"github.com/osolmaz/brokerkit/brokers/github/internal/opcatalog"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

// Presenter projects canonical GitHub grants into bounded display fields.
type Presenter struct{}

func (Presenter) Present(_ context.Context, grant grants.Grant) (approvalview.Presentation, error) {
	target := TargetSummary(grant.Target)
	if target == "" {
		return approvalview.Presentation{}, fmt.Errorf("GitHub grant %q has no target", grant.ID)
	}
	return approvalview.Presentation{
		Risk: risk(grant.Operation), Title: operationTitle(grant.Operation),
		Summary: "Review this GitHub operation before granting temporary access.",
		Target:  target, Facts: DisplayFacts(grant), Warnings: warnings(grant.Operation),
	}, nil
}

func operationTitle(operation string) string {
	if descriptor, found := opcatalog.ByName(operation); found {
		return approvalview.BoundedTitle("GitHub: " + strings.Join(strings.Fields(descriptor.Summary), " "))
	}
	return approvalview.BoundedTitle("GitHub: " + operation)
}

// TargetSummary renders the complete canonical target without exposing request payloads.
func TargetSummary(target policy.Target) string {
	kind := strings.TrimSpace(target.Kind)
	owner := policy.FirstValue(target.Fields["owner"])
	name := policy.FirstValue(target.Fields["name"])
	repo := policy.FirstValue(target.Fields["repo"])
	if kind == "repo" {
		return repositoryTarget(owner, name)
	}
	locator := targetLocator(target, owner, repo, name)
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

func targetLocator(target policy.Target, owner, repo, name string) string {
	return appendTargetQualifier(baseTargetLocator(target, owner, repo, name), target)
}

func baseTargetLocator(target policy.Target, owner, repo, name string) string {
	if owner != "" && repo != "" {
		return repositoryTarget(owner, repo)
	}
	locator := name
	if owner != "" && name != "" {
		return repositoryTarget(owner, name)
	}
	if locator != "" {
		return locator
	}
	if owner != "" {
		return owner
	}
	return policy.FirstValue(target.Fields["installation_account"])
}

func appendTargetQualifier(locator string, target policy.Target) string {
	if number := policy.FirstValue(target.Fields["number"]); number != "" {
		return strings.TrimSpace(locator + " #" + number)
	}
	for _, key := range []string{"id", "installation_id", "node_id"} {
		if value := policy.FirstValue(target.Fields[key]); value != "" {
			return strings.TrimSpace(locator + " " + value)
		}
	}
	return locator
}

// DisplayFacts returns the exact target and closed policy vocabulary used by every approval surface.
func DisplayFacts(grant grants.Grant) []approvalview.Fact {
	facts := []approvalview.Fact{{Label: "Operation", Value: grant.Operation}, {Label: "Target", Value: TargetSummary(grant.Target)}}
	targetLabels := map[string]string{"owner": "Target owner", "repo": "Target repository", "name": "Target name", "number": "Target number", "id": "Target ID", "node_id": "Target node ID",
		"installation_id": "Installation ID", "installation_account": "Installation account"}
	for _, key := range []string{"owner", "repo", "name", "number", "id", "node_id", "installation_id", "installation_account"} {
		if values := grant.Target.Fields[key]; len(values) > 0 {
			facts = append(facts, approvalview.Fact{Label: targetLabels[key], Value: strings.Join(values, ", ")})
		}
	}
	attributeLabels := map[string]string{ // #nosec G101 -- keys name non-secret policy metadata shown to the operator.
		"actor_id": "Actor ID", "actor_login": "Actor", "base_ref": "Base ref", "credential_kind": "Credential kind",
		"credential_slot": "Credential slot", "environment": "Environment", "head_ref": "Head ref", "label": "Labels",
		"merge_method": "Merge method", "path": "Path", "permission": "Permission", "ref": "Ref", "release_state": "Release state",
		"resource_id": "Resource ID", "resource_name": "Resource name", "resource_owner": "Resource owner", "role": "Role",
		"visibility": "Visibility", "workflow": "Workflow", "workflow_ref": "Workflow ref",
	}
	keys := make([]string, 0, len(grant.Attrs))
	for key := range grant.Attrs {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		if values := grant.Attrs[key]; len(values) > 0 {
			label := attributeLabels[key]
			if selector, found := strings.CutPrefix(key, "selector_"); found {
				label = "Selector " + strings.ReplaceAll(selector, "_", " ")
			}
			if label == "" {
				label = key
			}
			facts = append(facts, approvalview.Fact{Label: label, Value: strings.Join(values, ", ")})
		}
	}
	return facts
}

func risk(operation string) approvalview.Risk {
	if descriptor, found := opcatalog.ByName(operation); found {
		return approvalview.Risk(descriptor.Risk)
	}
	risks := map[string]approvalview.Risk{
		"git.fetch":              approvalview.RiskLow,
		"git.push.advertise":     approvalview.RiskMedium,
		"git.push.branch_create": approvalview.RiskHigh,
		"git.push.fast_forward":  approvalview.RiskHigh,
		"git.push.force":         approvalview.RiskCritical,
		"git.ref.delete":         approvalview.RiskCritical,
		"git.tag.update":         approvalview.RiskHigh,
		"webhook.github.receive": approvalview.RiskMedium,
	}
	if value, ok := risks[operation]; ok {
		return value
	}
	return approvalview.RiskUnknown
}

func warnings(operation string) []approvalview.Warning {
	risk := risk(operation)
	if risk != approvalview.RiskHigh && risk != approvalview.RiskCritical {
		return nil
	}
	return []approvalview.Warning{{Severity: risk, Text: "This GitHub operation may change or remove protected resources. Review the target and details carefully."}}
}
