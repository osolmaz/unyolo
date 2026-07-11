// Package approval provides shared approval-channel decision handling.
package approval

import (
	"context"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
)

// Decider applies one approval-channel decision through a broker's canonical lifecycle.
type Decider interface {
	Approve(context.Context, string, string, string, notify.MessageRef) (grants.Grant, error)
	Deny(context.Context, string, string, string, notify.MessageRef) (grants.Grant, error)
}

// HandleDecision maps a channel callback onto a durable broker decision.
func HandleDecision(ctx context.Context, decider Decider, decision notify.Decision) notify.DecisionResult {
	if decider == nil {
		return notify.DecisionResult{Retry: true}
	}
	actor := Actor(decision)
	ref := notify.MessageRef{Kind: "telegram", ChatID: decision.ChatID, MessageID: decision.MessageID, Text: decision.MessageText}
	var err error
	switch decision.Action {
	case notify.ActionApprove:
		_, err = decider.Approve(ctx, decision.GrantID, decision.DecisionToken, actor, ref)
		return result(err, "Grant approved")
	case notify.ActionDeny:
		_, err = decider.Deny(ctx, decision.GrantID, decision.DecisionToken, actor, ref)
		return result(err, "Grant denied")
	default:
		return notify.DecisionResult{Answer: "Grant decision ignored"}
	}
}

// Actor returns a stable audit identity for a channel decision.
func Actor(decision notify.Decision) string {
	if decision.OperatorID != 0 {
		return fmt.Sprintf("telegram:%d", decision.OperatorID)
	}
	if decision.OperatorTag != "" {
		return "telegram:@" + decision.OperatorTag
	}
	if decision.Approver != "" {
		return decision.Approver
	}
	return "telegram"
}

func result(err error, success string) notify.DecisionResult {
	if err == nil {
		return notify.DecisionResult{Answer: success}
	}
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return notify.DecisionResult{Answer: "Grant not found"}
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return notify.DecisionResult{Answer: "Grant decision token did not match"}
	case errors.Is(err, grants.ErrNotPending):
		return notify.DecisionResult{Answer: "Grant is no longer pending"}
	default:
		return notify.DecisionResult{Retry: true}
	}
}
