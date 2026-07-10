package httpapi

import (
	"context"
	"errors"
	"fmt"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
)

func (s *Server) handleTelegramDecision(_ context.Context, decision notify.Decision) notify.DecisionResult {
	actor := telegramActor(decision)
	message := notify.MessageRef{Kind: "telegram", ChatID: decision.ChatID, MessageID: decision.MessageID, Text: decision.MessageText}
	switch decision.Action {
	case notify.ActionApprove:
		_, err := s.grants.ApproveWithNotification(decision.GrantID, decision.DecisionToken, actor, message)
		return telegramDecisionResult(err, "Grant approved")
	case notify.ActionDeny:
		_, err := s.grants.DenyWithNotification(decision.GrantID, decision.DecisionToken, actor, message)
		return telegramDecisionResult(err, "Grant denied")
	default:
		return notify.DecisionResult{Answer: "Grant decision ignored"}
	}
}

func telegramDecisionResult(err error, successAnswer string) notify.DecisionResult {
	if err == nil {
		return notify.DecisionResult{Answer: successAnswer}
	}
	if errors.Is(err, grants.ErrNotFound) || errors.Is(err, grants.ErrInvalidDecisionToken) || errors.Is(err, grants.ErrNotPending) {
		return notify.DecisionResult{Answer: grantDecisionAnswer(err)}
	}
	return notify.DecisionResult{Retry: true}
}

func telegramActor(decision notify.Decision) string {
	if decision.OperatorTag != "" {
		return "telegram:@" + decision.OperatorTag
	}
	if decision.OperatorID != 0 {
		return fmt.Sprintf("telegram:%d", decision.OperatorID)
	}
	if decision.Approver != "" {
		return decision.Approver
	}
	return "telegram"
}

func grantDecisionAnswer(err error) string {
	switch {
	case errors.Is(err, grants.ErrNotFound):
		return "Grant not found"
	case errors.Is(err, grants.ErrInvalidDecisionToken):
		return "Grant decision token did not match"
	case errors.Is(err, grants.ErrNotPending):
		return "Grant is no longer pending"
	default:
		return "Grant decision failed"
	}
}
