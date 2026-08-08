package approval

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/osolmaz/unyolo/approval/view"
	unyologrants "github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfgrant"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hfplan"
	"github.com/osolmaz/unyolo/brokers/huggingface/internal/opcatalog"
)

const (
	targetNameField  = "name"
	targetRefField   = "refs"
	targetKindField  = "kind"
	targetTypeField  = "type"
	targetOwnerField = "owner"
	modeMetadata     = unyologrants.MetadataMode
)

// Presenter renders Hugging Face-specific wording without exposing execution authority.
type Presenter struct{}

// Present returns one bounded display projection for the shared operator inbox.
func (Presenter) Present(_ context.Context, grant unyologrants.Grant) (approvalview.Presentation, error) {
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
	if scope, ok := jobArgumentScope(grant); ok {
		facts = append(facts, approvalview.Fact{Label: "Job scope", Value: scope})
	}
	if digest := grant.Metadata[hfplan.MetadataDigest]; digest != "" {
		facts = append(facts, approvalview.Fact{Label: "Plan digest", Value: digest})
	}
	facts = append(facts, transactionFacts(grant)...)
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

func jobArgumentScope(grant unyologrants.Grant) (string, bool) {
	if grant.Operation != "job.run" && grant.Operation != "job.uv.run" {
		return "", false
	}
	if len(grant.Attrs["arguments_digest"]) == 0 {
		return "Any job arguments for this target", true
	}
	return "Exact job arguments only", true
}

func transactionFacts(grant unyologrants.Grant) []approvalview.Fact {
	attrs, err := hfgrant.Attrs(grant)
	if err != nil {
		return nil
	}
	var facts []approvalview.Fact
	if digest := transactionDigest(attrs); digest != "" {
		facts = append(facts, approvalview.Fact{Label: "Push body digest", Value: digest})
	}
	if commands := transactionCommands(attrs); commands != "" {
		facts = append(facts, approvalview.Fact{Label: "Push commands", Value: commands})
	}
	return facts
}

func transactionDigest(attrs map[string]any) string {
	digest, _ := attrs["plan_digest"].(string)
	return digest
}

func transactionCommands(attrs map[string]any) string {
	commands, ok := attrs["commands"]
	if !ok {
		return ""
	}
	encoded, err := json.Marshal(commands)
	if err != nil {
		return ""
	}
	return string(encoded)
}

func displayTarget(grant unyologrants.Grant) string {
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
