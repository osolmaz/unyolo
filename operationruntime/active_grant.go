package operationruntime

import (
	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/policy"
)

func (r *Runtime[I, P, A]) bindActiveGrant(operation agentv1.Operation, adapter Adapter[I, P, A], plan P,
	auth A, core policy.Request, decision policy.Decision) agentv1.Operation {
	grant, err := r.options.Grants.Get(decision.GrantID)
	if err != nil || !r.usableActiveGrant(grant, operation) {
		r.cleanup(adapter, plan)
		return r.fail(operation.ID, agentv1.StateFailed, "approval_unavailable", "Approved authority is no longer available")
	}
	intent, err := r.options.Prepare(Preparation[P, A]{Plan: plan, Auth: auth, Core: core,
		DescriptorName: adapter.Descriptor().Name, Client: operation.ClientID, OperationID: operation.ID,
		Reason: operation.Reason, Decision: decision, ReusedGrant: &grant, CreatedAt: r.now()})
	if err != nil || intent.Plan.Digest == "" {
		r.cleanup(adapter, plan)
		return r.fail(operation.ID, agentv1.StateFailed, "operation_plan_invalid", "Could not prepare immutable operation plan")
	}
	bound, err := r.options.Operations.BindPlan(operation.ID, PlanRecord(intent.Plan), grant.ID, false)
	if err != nil {
		r.cleanup(adapter, plan)
		return r.fail(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not bind operation plan")
	}
	approved, err := r.options.Operations.Transition(bound.ID, agentv1.StateApproved)
	if err != nil {
		r.cleanup(adapter, plan)
		return r.fail(operation.ID, agentv1.StateFailed, "operation_store_unavailable", "Could not activate approved operation")
	}
	return approved
}

func (r *Runtime[I, P, A]) usableActiveGrant(grant grants.Grant, operation agentv1.Operation) bool {
	return grant.Status == grants.StatusActive && !grant.ReservationRetained && grant.Client == operation.ClientID &&
		grant.Operation == operation.Operation && r.now().Before(grant.ExpiresAt) &&
		grant.MaxUses.Allows(grant.UsedCount, grant.ReservedCount) && r.options.ValidateExecution(grant) == nil
}
