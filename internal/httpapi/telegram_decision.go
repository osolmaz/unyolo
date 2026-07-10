package httpapi

import (
	"context"
	"errors"
	"fmt"

	bknotify "github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/hf-broker/internal/grants"
)

func (s *Server) handleTelegramDecision(_ context.Context, decision bknotify.Decision) bknotify.DecisionResult {
	actor := telegramActor(decision)
	message := grants.NotifierMessage{
		Kind:      "telegram",
		ChatID:    decision.ChatID,
		MessageID: decision.MessageID,
		Text:      decision.MessageText,
	}
	switch decision.Action {
	case bknotify.ActionApprove:
		_, err := s.grants.ApproveWithNotifier(decision.GrantID, decision.DecisionToken, actor, message)
		return telegramDecisionResult(err, "Grant approved")
	case bknotify.ActionDeny:
		_, err := s.grants.DenyWithNotifier(decision.GrantID, decision.DecisionToken, actor, message)
		return telegramDecisionResult(err, "Grant denied")
	default:
		return bknotify.DecisionResult{Answer: "Grant decision ignored"}
	}
}

func telegramDecisionResult(err error, successAnswer string) bknotify.DecisionResult {
	if err == nil {
		return bknotify.DecisionResult{Answer: successAnswer}
	}
	if errors.Is(err, grants.ErrNotFound) ||
		errors.Is(err, grants.ErrInvalidDecisionToken) ||
		errors.Is(err, grants.ErrNotPending) {
		return bknotify.DecisionResult{Answer: grantDecisionAnswer(err)}
	}
	return bknotify.DecisionResult{Retry: true}
}

func telegramActor(decision bknotify.Decision) string {
	if decision.OperatorTag != "" {
		return "telegram:@" + decision.OperatorTag
	}
	return fmt.Sprintf("telegram:%d", decision.OperatorID)
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
