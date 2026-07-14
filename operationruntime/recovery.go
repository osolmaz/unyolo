package operationruntime

import (
	"context"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/grants"
)

func (r *Runtime[I, P, A]) advancePendingApproval(ctx context.Context, operation agentv1.Operation) agentv1.Operation {
	if operation.State != agentv1.StatePending {
		return operation
	}
	if operation.ApprovalID == "" {
		operation = r.RecoverApproval(operation)
	}
	if operation.State != agentv1.StatePending || operation.ApprovalID == "" {
		return operation
	}
	operation = r.recoverApprovalNotification(ctx, operation)
	if operation.State == agentv1.StatePending {
		operation = r.syncApproval(operation)
	}
	return operation
}

func (r *Runtime[I, P, A]) recoverApprovalNotification(ctx context.Context, operation agentv1.Operation) agentv1.Operation {
	if r.options.Notifier == nil || r.options.ApprovalMessage == nil {
		return operation
	}
	grant, err := r.options.Grants.Get(operation.ApprovalID)
	if err != nil || grant.Status != grants.StatusPending || grant.Notification != nil {
		return operation
	}
	return r.bindApproval(ctx, operation, grant)
}
