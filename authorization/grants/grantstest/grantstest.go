// Package grantstest decides grants in tests through the Operator V1
// decision path, as an operator would.
package grantstest

import (
	"context"
	"fmt"

	"github.com/osolmaz/unyolo/authorization/grants"
)

// Approve approves a pending grant at its current revision.
func Approve(store *grants.Store, id, approver string) (grants.Grant, error) {
	return decide(store, id, approver, grants.ActionApprove)
}

// Deny denies a pending grant at its current revision.
func Deny(store *grants.Store, id, approver string) (grants.Grant, error) {
	return decide(store, id, approver, grants.ActionDeny)
}

func decide(store *grants.Store, id, approver string, action grants.DecisionAction) (grants.Grant, error) {
	current, err := store.Get(id)
	if err != nil {
		return grants.Grant{}, err
	}
	result, err := store.ApplyOperatorDecision(context.Background(), grants.OperatorDecision{
		ID: id, Action: action, Approver: approver, ExpectedRevision: current.Revision,
		IdempotencyKey: fmt.Sprintf("test-%s-%s-%d", action, id, current.Revision),
	}, nil)
	return result.Grant, err
}
