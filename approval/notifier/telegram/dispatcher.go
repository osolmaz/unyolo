package telegram

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/osolmaz/unyolo/approval"
	"github.com/osolmaz/unyolo/approval/notification"
	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/operator/client"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/protocol/contract"
)

// OperatorSource is the trusted Operator V1 surface needed by Telegram ingress.
type OperatorSource interface {
	Get(context.Context, string) (operatorv1.Request, error)
	Decide(context.Context, string, operatorv1.Action, operatorv1.Decision) (operatorv1.Request, error)
}

type readyOperatorSource interface {
	Discover(context.Context) (operatorv1.Descriptor, error)
	Health(context.Context) error
}

// Dispatcher sends callbacks from one Telegram poller to broker Operator V1 sources.
type Dispatcher struct {
	routes map[string]OperatorSource
}

var terminalDecisionAnswers = map[grants.Status]notify.Answer{
	grants.StatusActive:   notify.AnswerApproved,
	grants.StatusDenied:   notify.AnswerDenied,
	grants.StatusExpired:  notify.AnswerAlreadyExpired,
	grants.StatusConsumed: notify.AnswerAlreadyConsumed,
	grants.StatusRevoked:  notify.AnswerAlreadyRevoked,
	grants.StatusCanceled: notify.AnswerAlreadyCanceled,
}

var routeBrokerNames = map[string]string{
	RouteHuggingFace: "Hugging Face",
	RouteGitHub:      "GitHub",
	RouteSudo:        "sudo",
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

// Ready verifies exact authenticated discovery and health for every route.
func (d *Dispatcher) Ready(ctx context.Context) error {
	for route, source := range d.routes {
		ready, ok := source.(readyOperatorSource)
		if !ok {
			return fmt.Errorf("telegram dispatcher route %q has no readiness contract", route)
		}
		descriptor, err := ready.Discover(ctx)
		if err != nil || !compatibleDescriptor(descriptor) {
			return fmt.Errorf("telegram dispatcher route %q contract is unavailable", route)
		}
		if err := ready.Health(ctx); err != nil {
			return fmt.Errorf("telegram dispatcher route %q is unhealthy", route)
		}
	}
	return nil
}

// Compatible rejects exact contract drift while allowing temporary route
// outages to enter the durable per-route retry path.
func (d *Dispatcher) Compatible(ctx context.Context) error {
	for route, source := range d.routes {
		ready, ok := source.(readyOperatorSource)
		if !ok {
			return fmt.Errorf("telegram dispatcher route %q has no readiness contract", route)
		}
		descriptor, err := ready.Discover(ctx)
		if errors.Is(err, operatorclient.ErrContractMismatch) || (err == nil && !compatibleDescriptor(descriptor)) {
			return fmt.Errorf("telegram dispatcher route %q has an incompatible contract", route)
		}
	}
	return nil
}

func compatibleDescriptor(descriptor operatorv1.Descriptor) bool {
	return descriptor.APIVersion == operatorv1.APIVersion && descriptor.ContractDigest == contract.OperatorV1Digest && descriptor.BuildID != ""
}

// Handle applies one routed callback through the owning broker's Operator V1 API.
func (d *Dispatcher) Handle(ctx context.Context, decision notify.Decision) notify.DecisionResult {
	ctx, cancel := context.WithTimeout(ctx, operatorDecisionTimeout)
	defer cancel()
	source, ok := d.routes[decision.Route]
	if !ok {
		return notify.DecisionResult{Answer: notify.AnswerRouteUnavailable, MessageStatus: notify.Status{Kind: notify.StatusClosed}}
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
		return notify.DecisionResult{Answer: notify.AnswerIgnored}
	}
	notification, err := notificationDecision(current, decision)
	if err != nil {
		return notify.DecisionResult{Answer: notify.AnswerUnavailable}
	}
	updated, err := source.Decide(ctx, current.ID, action, operatorv1.Decision{
		ExpectedRevision: current.Revision,
		IdempotencyKey:   callbackIdempotencyKey(decision),
		OnBehalfOf:       approval.Actor(decision),
		Notification:     notification,
	})
	if err != nil {
		return dispatcherErrorResult(err)
	}
	return completedDecisionResult(updated)
}

func notificationDecision(request operatorv1.Request, decision notify.Decision) (*operatorv1.NotificationDecision, error) {
	semantic, err := semanticApproval(request, decision.Route, decision.DecisionToken)
	if err != nil {
		return nil, err
	}
	text, err := RenderApproval(semantic)
	if err != nil {
		return nil, err
	}
	return &operatorv1.NotificationDecision{
		Kind: "telegram", Renderer: rendererID, DecisionToken: decision.DecisionToken,
		ChatID: decision.ChatID, MessageID: decision.MessageID, Text: text,
		PresentationJSON: approvalnotify.SnapshotJSON(semantic), PresentationDigest: approvalnotify.PresentationDigest(semantic),
		RenderedDigest: renderedDigest(text),
	}, nil
}

func semanticApproval(request operatorv1.Request, route, token string) (approvalnotify.Approval, error) {
	broker := routeBrokerNames[route]
	if broker == "" || request.PendingExpiresAt == nil {
		return approvalnotify.Approval{}, errors.New("pending notification presentation is unavailable")
	}
	facts := make([]approvalview.Fact, len(request.Presentation.Facts))
	for index, fact := range request.Presentation.Facts {
		facts[index] = approvalview.Fact{Label: fact.Label, Value: fact.Value}
	}
	warnings := make([]approvalview.Warning, len(request.Presentation.Warnings))
	for index, warning := range request.Presentation.Warnings {
		warnings[index] = approvalview.Warning{Severity: approvalview.Risk(warning.Severity), Text: warning.Text}
	}
	return approvalnotify.Approval{
		GrantID: request.ID, DecisionToken: token, Broker: broker, Requester: request.Requester,
		Operation: request.Operation, Reason: request.RequestReason, RequestedDurationSeconds: request.RequestedDurationSeconds,
		MaxUses: request.GrantedMaxUses, PendingExpiresAt: *request.PendingExpiresAt,
		Presentation: approvalview.Presentation{Risk: approvalview.Risk(request.Presentation.Risk), Title: request.Presentation.Title,
			Summary: request.Presentation.Summary, Target: request.Presentation.Target, Facts: facts, Warnings: warnings,
			PlanHash: request.Presentation.PlanHash},
		PresentationUnavailable: request.PresentationUnavailable,
	}, nil
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
			return notify.DecisionResult{Answer: notify.AnswerNotFound, MessageStatus: notify.Status{Kind: notify.StatusUnavailable}}
		}
		if apiError.Code == "invalid_decision_token" {
			return notify.DecisionResult{Answer: notify.AnswerSuperseded, MessageStatus: notify.Status{Kind: notify.StatusSuperseded}}
		}
	}
	return notify.DecisionResult{Answer: notify.AnswerUnavailable}
}

func completedDecisionResult(request operatorv1.Request) notify.DecisionResult {
	answer := terminalDecisionAnswers[request.Status]
	if answer == "" {
		answer = notify.AnswerClosed
	}
	if request.Status == grants.StatusPending {
		return notify.DecisionResult{Answer: answer}
	}
	return notify.DecisionResult{Answer: answer, MessageStatus: statusForRequest(request)}
}

func statusForRequest(request operatorv1.Request) notify.Status {
	status := notify.Status{UsedCount: request.UsedCount, MaxUses: request.GrantedMaxUses}
	if request.Status == grants.StatusExpired {
		if request.ActiveExpiresAt == nil {
			status.Kind = notify.StatusPendingExpired
		} else {
			status.Kind = notify.StatusActiveExpired
		}
		return status
	}
	status.Kind = map[grants.Status]notify.StatusKind{
		grants.StatusActive: notify.StatusActive, grants.StatusDenied: notify.StatusDenied,
		grants.StatusConsumed: notify.StatusConsumed, grants.StatusRevoked: notify.StatusRevoked,
		grants.StatusCanceled: notify.StatusCanceled,
	}[request.Status]
	if status.Kind == "" {
		status.Kind = notify.StatusClosed
	}
	return status
}
