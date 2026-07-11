package approval

import (
	"context"
	"fmt"

	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
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
	if risk, ok := operationRisks[hfpolicy.Operation(operation)]; ok {
		return risk
	}
	return operatorinbox.RiskUnknown
}

var operationRisks = map[hfpolicy.Operation]operatorinbox.Risk{
	hfpolicy.OpRepoList:          operatorinbox.RiskLow,
	hfpolicy.OpRepoMetadataRead:  operatorinbox.RiskLow,
	hfpolicy.OpRepoContentsRead:  operatorinbox.RiskLow,
	hfpolicy.OpGitFetch:          operatorinbox.RiskLow,
	hfpolicy.OpGitPushAppend:     operatorinbox.RiskHigh,
	hfpolicy.OpGitPushForce:      operatorinbox.RiskCritical,
	hfpolicy.OpGitRefDelete:      operatorinbox.RiskCritical,
	hfpolicy.OpGitTagUpdate:      operatorinbox.RiskHigh,
	hfpolicy.OpBucketObjectList:  operatorinbox.RiskLow,
	hfpolicy.OpBucketObjectRead:  operatorinbox.RiskLow,
	hfpolicy.OpBucketObjectWrite: operatorinbox.RiskHigh,
	hfpolicy.OpBucketObjectDel:   operatorinbox.RiskCritical,
	hfpolicy.OpInferenceModels:   operatorinbox.RiskLow,
	hfpolicy.OpInferenceChat:     operatorinbox.RiskMedium,
}

func titleForOperation(operation string) string {
	return "Hugging Face: " + operationText(operation)
}
