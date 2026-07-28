package operationruntime

import (
	"context"
	"errors"

	"github.com/osolmaz/unyolo/agent/runtime"
	"github.com/osolmaz/unyolo/agent/v1"
	"github.com/osolmaz/unyolo/authorization"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/authorization/policy"
)

func (r *Runtime[I, P, A]) submitDirectGrant(submission agentops.Submit, adapter Adapter[I, P, A], plan P,
	auth A, core policy.Request, decision policy.Decision) (agentv1.Operation, bool, error) {
	intent, err := r.options.Prepare(Preparation[P, A]{Plan: plan, Auth: auth, Core: core,
		DescriptorName: adapter.Descriptor().Name, Client: submission.ClientID, OperationID: submission.ID,
		Reason: submission.Reason, Decision: decision, Direct: true, CreatedAt: r.now()})
	if err != nil {
		r.cleanup(adapter, plan)
		return agentv1.Operation{}, false, err
	}
	operation, created, err := r.options.Operations.SubmitApprovedWithPlan(submission, PlanRecord(intent.Plan))
	if err != nil {
		r.cleanup(adapter, plan)
	}
	return operation, created, err
}

func (r *Runtime[I, P, A]) submitWithAvailableGrant(ctx context.Context, submission agentops.Submit,
	adapter Adapter[I, P, A], plan P, auth A, core policy.Request) (agentv1.Operation, bool, error) {
	decision, found, err := r.options.Authorization.ActiveGrant(core)
	if err != nil {
		r.cleanup(adapter, plan)
		return agentv1.Operation{}, false, err
	}
	if found {
		return r.submitActiveGrant(submission, adapter, plan, auth, core, decision)
	}
	return r.submitPending(ctx, submission, adapter, plan, auth, core)
}

func (r *Runtime[I, P, A]) submitActiveGrant(submission agentops.Submit, adapter Adapter[I, P, A], plan P,
	auth A, core policy.Request, decision policy.Decision) (agentv1.Operation, bool, error) {
	grant, intent, err := r.prepareActiveGrant(submission, adapter, plan, auth, core, decision)
	if err != nil {
		r.cleanup(adapter, plan)
		return agentv1.Operation{}, false, err
	}
	operation, created, err := r.options.Operations.SubmitApprovedWithGrantPlan(submission, PlanRecord(intent.Plan), grant.ID)
	if err != nil {
		r.cleanup(adapter, plan)
	}
	return operation, created, err
}

func (r *Runtime[I, P, A]) prepareActiveGrant(submission agentops.Submit, adapter Adapter[I, P, A], plan P,
	auth A, core policy.Request, decision policy.Decision) (grants.Grant, authorization.GrantIntent, error) {
	grant, err := r.options.Grants.Get(decision.GrantID)
	if err != nil || !r.usableActiveGrant(grant, submission) {
		return grants.Grant{}, authorization.GrantIntent{}, errors.New("approved authority is no longer available")
	}
	intent, err := r.options.Prepare(Preparation[P, A]{Plan: plan, Auth: auth, Core: core,
		DescriptorName: adapter.Descriptor().Name, Client: submission.ClientID, OperationID: submission.ID,
		Reason: submission.Reason, Decision: decision, ReusedGrant: &grant, CreatedAt: r.now()})
	if err != nil || intent.Plan.Digest == "" {
		return grants.Grant{}, authorization.GrantIntent{}, errors.New("could not prepare immutable operation plan")
	}
	return grant, intent, nil
}

func (r *Runtime[I, P, A]) usableActiveGrant(grant grants.Grant, submission agentops.Submit) bool {
	return grant.Status == grants.StatusActive && !grant.ReservationRetained && grant.Client == submission.ClientID &&
		grant.Operation == submission.Operation && r.now().Before(grant.ExpiresAt) &&
		grant.MaxUses.Allows(grant.UsedCount, grant.ReservedCount) && r.options.ValidateExecution(grant) == nil
}
