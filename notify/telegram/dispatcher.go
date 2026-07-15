package telegram

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/osolmaz/brokerkit/approval"
	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorv1"
)

// OperatorSource is the trusted Operator V1 surface needed by Telegram ingress.
type OperatorSource interface {
	Get(context.Context, string) (operatorv1.Request, error)
	Decide(context.Context, string, operatorv1.Action, operatorv1.Decision) (operatorv1.Request, error)
}

// Dispatcher sends callbacks from one Telegram poller to broker Operator V1 sources.
type Dispatcher struct {
	routes map[string]OperatorSource
}

var terminalDecisionAnswers = map[grants.Status]string{
	grants.StatusActive:   "Grant approved",
	grants.StatusDenied:   "Grant denied",
	grants.StatusExpired:  "Grant expired",
	grants.StatusConsumed: "Grant already used",
	grants.StatusRevoked:  "Grant revoked",
	grants.StatusCanceled: "Grant canceled",
}

const operatorDecisionTimeout = 15 * time.Second

// NewDispatcher builds a single-ingress route dispatcher.
func NewDispatcher(routes map[string]OperatorSource) (*Dispatcher, error) {
	if len(routes) == 0 {
		return nil, errors.New("telegram dispatcher requires at least one route")
	}
	cloned := make(map[string]OperatorSource, len(routes))
	for route, source := range routes {
		if !validRoute(route) || source == nil {
			return nil, fmt.Errorf("telegram dispatcher route %q is invalid", route)
		}
		cloned[route] = source
	}
	return &Dispatcher{routes: cloned}, nil
}

// Handle applies one routed callback through the owning broker's Operator V1 API.
func (d *Dispatcher) Handle(ctx context.Context, decision notify.Decision) notify.DecisionResult {
	ctx, cancel := context.WithTimeout(ctx, operatorDecisionTimeout)
	defer cancel()
	source, ok := d.routes[decision.Route]
	if !ok {
		return notify.DecisionResult{Answer: "Approval route is unavailable", ClearButtons: true}
	}
	current, err := source.Get(ctx, decision.GrantID)
	if err != nil {
		return dispatcherErrorResult(err)
	}
	if current.Status != grants.StatusPending {
		return completedDecisionResult(current)
	}
	action, ok := operatorAction(decision.Action)
	if !ok {
		return notify.DecisionResult{Answer: "Grant decision ignored"}
	}
	updated, err := source.Decide(ctx, current.ID, action, operatorv1.Decision{
		ExpectedRevision: current.Revision,
		IdempotencyKey:   callbackIdempotencyKey(decision),
		OnBehalfOf:       approval.Actor(decision),
		Notification: &operatorv1.NotificationDecision{Kind: "telegram", DecisionToken: decision.DecisionToken,
			ChatID: decision.ChatID, MessageID: decision.MessageID, Text: decision.MessageText},
	})
	if err != nil {
		return dispatcherErrorResult(err)
	}
	return completedDecisionResult(updated)
}

func operatorAction(action notify.Action) (operatorv1.Action, bool) {
	switch action {
	case notify.ActionApprove:
		return operatorv1.ActionApprove, true
	case notify.ActionDeny:
		return operatorv1.ActionDeny, true
	default:
		return "", false
	}
}

func callbackIdempotencyKey(decision notify.Decision) string {
	digest := sha256.Sum256([]byte(decision.Route + "\x00" + decision.CallbackID + "\x00" + decision.DecisionToken))
	return "telegram-" + base64.RawURLEncoding.EncodeToString(digest[:])
}

func dispatcherErrorResult(err error) notify.DecisionResult {
	var apiError *operatorclient.Error
	if errors.As(err, &apiError) {
		if apiError.Current != nil && apiError.Current.Status != grants.StatusPending {
			return completedDecisionResult(*apiError.Current)
		}
		if apiError.Status == 404 {
			return notify.DecisionResult{Answer: "Grant not found", ClearButtons: true}
		}
		if apiError.Code == "invalid_decision_token" {
			return notify.DecisionResult{Answer: "Approval request was superseded", ClearButtons: true}
		}
	}
	return notify.DecisionResult{Answer: "Broker temporarily unavailable; try again"}
}

func completedDecisionResult(request operatorv1.Request) notify.DecisionResult {
	answer := terminalDecisionAnswers[request.Status]
	if answer == "" {
		answer = "Grant is no longer pending"
	}
	return notify.DecisionResult{Answer: answer, ClearButtons: request.Status != grants.StatusPending}
}
