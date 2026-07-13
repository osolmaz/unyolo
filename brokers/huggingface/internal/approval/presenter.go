package approval

import (
	"context"
	"fmt"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/opcatalog"
	bkgrants "github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/operatorinbox"
	"github.com/osolmaz/brokerkit/policy"
)

const (
	targetNameField = "name"
	targetRefField  = "ref"
	modeMetadata    = "hf_grant_mode"
)

// Presenter renders Hugging Face-specific wording without exposing execution authority.
type Presenter struct{}

// Present returns one bounded display projection for the shared operator inbox.
func (Presenter) Present(_ context.Context, grant bkgrants.Grant) (operatorinbox.Presentation, error) {
	target := policy.FirstValue(grant.Target.Fields[targetNameField])
	if target == "" {
		return operatorinbox.Presentation{}, fmt.Errorf("HF grant %q has no target", grant.ID)
	}
	fields := []operatorinbox.DisplayField{{Label: "Operation", Value: operationText(grant.Operation)}}
	if ref := policy.FirstValue(grant.Target.Fields[targetRefField]); ref != "" {
		fields = append(fields, operatorinbox.DisplayField{Label: "Ref", Value: ref})
	}
	if mode := grant.Metadata[modeMetadata]; mode != "" {
		fields = append(fields, operatorinbox.DisplayField{Label: "Mode", Value: mode})
	}
	if grant.ReservationRetained {
		fields = append(fields, operatorinbox.DisplayField{Label: "Needs attention", Value: "Execution result is ambiguous; authority is closed"})
	}
	return operatorinbox.Presentation{
		Risk: riskForOperation(grant.Operation), Title: titleForOperation(grant.Operation),
		Summary: "Review this Hugging Face operation before granting temporary access.",
		Target:  target, Fields: fields,
	}, nil
}

func riskForOperation(operation string) operatorinbox.Risk {
	descriptor, ok := opcatalog.ByName(operation)
	if !ok {
		return operatorinbox.RiskUnknown
	}
	switch descriptor.Risk {
	case opcatalog.RiskLow:
		return operatorinbox.RiskLow
	case opcatalog.RiskMedium:
		return operatorinbox.RiskMedium
	case opcatalog.RiskHigh:
		return operatorinbox.RiskHigh
	case opcatalog.RiskCritical:
		return operatorinbox.RiskCritical
	default:
		return operatorinbox.RiskUnknown
	}
}

func titleForOperation(operation string) string {
	return "Hugging Face: " + operationText(operation)
}
