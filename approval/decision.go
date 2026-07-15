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
		return notify.DecisionResult{Answer: "Grant not found", MessageStatus: "Unavailable. Grant no longer exists."}
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
		return notify.DecisionResult{Answer: "Grant already approved", MessageStatus: StatusMessage(status)}
	case grants.StatusDenied:
		return notify.DecisionResult{Answer: "Grant already denied", MessageStatus: StatusMessage(status)}
	case grants.StatusExpired:
		return notify.DecisionResult{Answer: "Grant already expired", MessageStatus: StatusMessage(status)}
	case grants.StatusConsumed:
		return notify.DecisionResult{Answer: "Grant already used", MessageStatus: StatusMessage(status)}
	case grants.StatusRevoked:
		return notify.DecisionResult{Answer: "Grant already revoked", MessageStatus: StatusMessage(status)}
	case grants.StatusCanceled:
		return notify.DecisionResult{Answer: "Grant already canceled", MessageStatus: StatusMessage(status)}
	default:
		return notify.DecisionResult{Answer: "Grant is no longer pending", MessageStatus: "Closed. Approval request is no longer pending."}
	}
}

// StatusMessage returns provider-neutral operator wording for a grant status.
func StatusMessage(status grants.Status) string {
	switch status {
	case grants.StatusActive:
		return "Approved. Access is active."
	case grants.StatusDenied:
		return "Denied. Access was not granted."
	case grants.StatusExpired:
		return "Expired. Access is closed."
	case grants.StatusConsumed:
		return "Used. Access is now closed."
	case grants.StatusRevoked:
		return "Revoked. Access is closed."
	case grants.StatusCanceled:
		return "Canceled. Approval request is closed."
	default:
		return "Grant status changed."
	}
}

// StatusUpdateMessage returns provider-neutral wording for a durable notification update.
func StatusUpdateMessage(update grants.StatusUpdate) string {
	switch update.Kind {
	case grants.StatusUpdateRetainedReservation:
		return "Result is ambiguous. Access is closed until an operator reviews the retained use."
	case grants.StatusUpdateUsed, grants.StatusUpdateUsedExpired:
		if update.Grant.Status == grants.StatusActive {
			return "Used. Access remains active until its limit or expiry."
		}
		return "Used. Access is now closed."
	default:
		return StatusMessage(update.Status)
	}
}
