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
	var grant grants.Grant
	var err error
	switch decision.Action {
	case notify.ActionApprove:
		grant, err = decider.Approve(ctx, decision.GrantID, decision.DecisionToken, actor, ref)
		return result(grant, err, "Grant approved", "Approved. Access is active.")
	case notify.ActionDeny:
		grant, err = decider.Deny(ctx, decision.GrantID, decision.DecisionToken, actor, ref)
		return result(grant, err, "Grant denied", "Denied. Access was not granted.")
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

func result(grant grants.Grant, err error, success, successStatus string) notify.DecisionResult {
	if err == nil {
		return notify.DecisionResult{Answer: success, MessageStatus: successStatus}
	}
	switch {
	case errors.Is(err, grants.ErrNotFound):
		// Several brokers may share one Telegram bot. Leave an unknown grant
		// unacknowledged so the broker that owns it can consume the update.
		return notify.DecisionResult{Retry: true}
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return notify.DecisionResult{Answer: "Grant decision token did not match"}
	case errors.Is(err, grants.ErrNotPending):
		return terminalResult(grant.Status)
	default:
		return notify.DecisionResult{Retry: true}
	}
}

func terminalResult(status grants.Status) notify.DecisionResult {
	switch status {
	case grants.StatusActive:
		return notify.DecisionResult{Answer: "Grant already approved", MessageStatus: "Approved. Access is active."}
	case grants.StatusDenied:
		return notify.DecisionResult{Answer: "Grant already denied", MessageStatus: "Denied. Access was not granted."}
	case grants.StatusExpired:
		return notify.DecisionResult{Answer: "Grant already expired", MessageStatus: "Expired. Access is closed."}
	case grants.StatusConsumed:
		return notify.DecisionResult{Answer: "Grant already used", MessageStatus: "Used. Access is now closed."}
	case grants.StatusRevoked:
		return notify.DecisionResult{Answer: "Grant already revoked", MessageStatus: "Revoked. Access is closed."}
	case grants.StatusCanceled:
		return notify.DecisionResult{Answer: "Grant already canceled", MessageStatus: "Canceled. Approval request is closed."}
	default:
		return notify.DecisionResult{Answer: "Grant is no longer pending", MessageStatus: "Closed. Approval request is no longer pending."}
	}
}
