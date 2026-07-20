package approval

import (
	"context"
	"fmt"

	"github.com/osolmaz/brokerkit/approval/view"
	bkgrants "github.com/osolmaz/brokerkit/authorization/grants"
	"github.com/osolmaz/brokerkit/authorization/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
)

const (
	targetNameField  = "name"
	targetRefField   = "refs"
	targetKindField  = "kind"
	targetTypeField  = "type"
	targetOwnerField = "owner"
	modeMetadata     = "hf_grant_mode"
)

// Presenter renders Hugging Face-specific wording without exposing execution authority.
type Presenter struct{}

// Present returns one bounded display projection for the shared operator inbox.
func (Presenter) Present(_ context.Context, grant bkgrants.Grant) (approvalview.Presentation, error) {
	target := displayTarget(grant)
	if target == "" {
		return approvalview.Presentation{}, fmt.Errorf("HF grant %q has no target", grant.ID)
	}
	facts := []approvalview.Fact{{Label: "Operation", Value: operationText(grant.Operation)}}
	if ref := policy.FirstValue(grant.Target.Fields[targetRefField]); ref != "" {
		facts = append(facts, approvalview.Fact{Label: "Ref", Value: ref})
	}
	if mode := grant.Metadata[modeMetadata]; mode != "" {
		facts = append(facts, approvalview.Fact{Label: "Mode", Value: mode})
	}
	if digest := grant.Metadata[hfplan.MetadataDigest]; digest != "" {
		facts = append(facts, approvalview.Fact{Label: "Plan digest", Value: digest})
	}
	if grant.ReservationRetained {
		facts = append(facts, approvalview.Fact{Label: "Needs attention", Value: "Execution result is ambiguous; authority is closed"})
	}
	title := grant.Metadata[hfplan.MetadataTitle]
	if title == "" {
		title = titleForOperation(grant.Operation)
	}
	summary := grant.Metadata[hfplan.MetadataSummary]
	if summary == "" {
		summary = "Review this Hugging Face operation before granting temporary access."
	}
	return approvalview.Presentation{
		Risk: riskForOperation(grant.Operation), Title: title,
		Summary: summary,
		Target:  target, Facts: facts, Warnings: warnings(grant.Operation), PlanHash: grant.Metadata[hfplan.MetadataDigest],
	}, nil
}

func displayTarget(grant bkgrants.Grant) string {
	fields := grant.Target.Fields
	name := policy.FirstValue(fields[targetNameField])
	kind := policy.FirstValue(fields[targetKindField])
	if kind == "" {
		return name
	}
	owner := policy.FirstValue(fields[targetOwnerField])
	if kind == "repo" {
		kind = policy.FirstValue(fields[targetTypeField])
	}
	return kind + "/" + owner + "/" + name
}

func riskForOperation(operation string) approvalview.Risk {
	descriptor, ok := opcatalog.ByName(operation)
	if !ok {
		return approvalview.RiskUnknown
	}
	switch descriptor.Risk {
	case opcatalog.RiskLow:
		return approvalview.RiskLow
	case opcatalog.RiskMedium:
		return approvalview.RiskMedium
	case opcatalog.RiskHigh:
		return approvalview.RiskHigh
	case opcatalog.RiskCritical:
		return approvalview.RiskCritical
	default:
		return approvalview.RiskUnknown
	}
}

func warnings(operation string) []approvalview.Warning {
	risk := riskForOperation(operation)
	if risk != approvalview.RiskHigh && risk != approvalview.RiskCritical {
		return nil
	}
	return []approvalview.Warning{{Severity: risk, Text: "This Hugging Face operation may change or remove protected resources. Review the target and details carefully."}}
}

func titleForOperation(operation string) string {
	return "Hugging Face: " + operationText(operation)
}
