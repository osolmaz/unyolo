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
	if decision.Notification != nil {
		ref = *decision.Notification
	}
	var grant grants.Grant
	var err error
	switch decision.Action {
	case notify.ActionApprove:
		grant, err = decider.Approve(ctx, decision.GrantID, decision.DecisionToken, actor, ref)
		return result(grant, err, notify.AnswerApproved, notify.StatusActive)
	case notify.ActionDeny:
		grant, err = decider.Deny(ctx, decision.GrantID, decision.DecisionToken, actor, ref)
		return result(grant, err, notify.AnswerDenied, notify.StatusDenied)
	default:
		return notify.DecisionResult{Answer: notify.AnswerIgnored}
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

func result(grant grants.Grant, err error, success notify.Answer, successStatus notify.StatusKind) notify.DecisionResult {
	if err == nil {
		return notify.DecisionResult{Answer: success, MessageStatus: notify.Status{Kind: successStatus, MaxUses: grant.MaxUses}}
	}
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return notify.DecisionResult{Answer: notify.AnswerNotFound, MessageStatus: notify.Status{Kind: notify.StatusUnavailable}}
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return notify.DecisionResult{Answer: notify.AnswerSuperseded}
	case errors.Is(err, grants.ErrNotPending):
		return terminalResult(grant)
	default:
		return notify.DecisionResult{Retry: true}
	}
}

func terminalResult(grant grants.Grant) notify.DecisionResult {
	status := StatusForGrant(grant)
	switch grant.Status {
	case grants.StatusActive:
		return notify.DecisionResult{Answer: notify.AnswerAlreadyApproved, MessageStatus: status}
	case grants.StatusDenied:
		return notify.DecisionResult{Answer: notify.AnswerAlreadyDenied, MessageStatus: status}
	case grants.StatusExpired:
		return notify.DecisionResult{Answer: notify.AnswerAlreadyExpired, MessageStatus: status}
	case grants.StatusConsumed:
		return notify.DecisionResult{Answer: notify.AnswerAlreadyConsumed, MessageStatus: status}
	case grants.StatusRevoked:
		return notify.DecisionResult{Answer: notify.AnswerAlreadyRevoked, MessageStatus: status}
	case grants.StatusCanceled:
		return notify.DecisionResult{Answer: notify.AnswerAlreadyCanceled, MessageStatus: status}
	default:
		return notify.DecisionResult{Answer: notify.AnswerClosed, MessageStatus: notify.Status{Kind: notify.StatusClosed}}
	}
}

// StatusForGrant maps a canonical grant onto a channel-neutral presentation state.
func StatusForGrant(grant grants.Grant) notify.Status {
	status := notify.Status{UsedCount: grant.UsedCount, ReservedCount: grant.ReservedCount, MaxUses: grant.MaxUses}
	switch grant.Status {
	case grants.StatusActive:
		status.Kind = notify.StatusActive
	case grants.StatusDenied:
		status.Kind = notify.StatusDenied
	case grants.StatusExpired:
		if grant.ExpiredFrom == grants.StatusPending {
			status.Kind = notify.StatusPendingExpired
		} else {
			status.Kind = notify.StatusActiveExpired
		}
	case grants.StatusConsumed:
		status.Kind = notify.StatusConsumed
	case grants.StatusRevoked:
		status.Kind = notify.StatusRevoked
	case grants.StatusCanceled:
		status.Kind = notify.StatusCanceled
	default:
		status.Kind = notify.StatusClosed
	}
	return status
}

// StatusForUpdate maps a durable notification update onto a presentation state.
func StatusForUpdate(update grants.StatusUpdate) notify.Status {
	status := notify.Status{UsedCount: update.Grant.UsedCount, ReservedCount: update.Grant.ReservedCount, MaxUses: update.Grant.MaxUses}
	switch update.Kind {
	case grants.StatusUpdateRetainedReservation:
		status.Kind = notify.StatusRetained
	case grants.StatusUpdateUsed, grants.StatusUpdateUsedExpired:
		if update.Grant.Status == grants.StatusActive {
			status.Kind = notify.StatusUsedActive
		} else {
			status.Kind = notify.StatusConsumed
		}
	default:
		status = StatusForGrant(update.Grant)
		if update.Grant.Status == "" {
			status = StatusForGrant(grants.Grant{Status: update.Status})
		}
	}
	return status
}
