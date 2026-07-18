package operationruntime

import (
	"errors"

	"github.com/osolmaz/brokerkit/agentops"
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

func (r *Runtime[I, P, A]) submitActiveGrant(submission agentops.Submit, adapter Adapter[I, P, A], plan P,
	auth A, core policy.Request, decision policy.Decision) (agentv1.Operation, bool, error) {
	grant, err := r.options.Grants.Get(decision.GrantID)
	if err != nil || !r.usableActiveGrant(grant, submission) {
		r.cleanup(adapter, plan)
		return agentv1.Operation{}, false, errors.New("approved authority is no longer available")
	}
	intent, err := r.options.Prepare(Preparation[P, A]{Plan: plan, Auth: auth, Core: core,
		DescriptorName: adapter.Descriptor().Name, Client: submission.ClientID, OperationID: submission.ID,
		Reason: submission.Reason, Decision: decision, ReusedGrant: &grant, CreatedAt: r.now()})
	if err != nil || intent.Plan.Digest == "" {
		r.cleanup(adapter, plan)
		return agentv1.Operation{}, false, errors.New("could not prepare immutable operation plan")
	}
	operation, created, err := r.options.Operations.SubmitApprovedWithGrantPlan(submission, PlanRecord(intent.Plan), grant.ID)
	if err != nil {
		r.cleanup(adapter, plan)
	}
	return operation, created, err
}

func (r *Runtime[I, P, A]) usableActiveGrant(grant grants.Grant, submission agentops.Submit) bool {
	return grant.Status == grants.StatusActive && !grant.ReservationRetained && grant.Client == submission.ClientID &&
		grant.Operation == submission.Operation && r.now().Before(grant.ExpiresAt) &&
		grant.MaxUses.Allows(grant.UsedCount, grant.ReservedCount) && r.options.ValidateExecution(grant) == nil
}
