package telegram

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

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

// cardVerifier checks that a click belongs to a card the owner sent.
type cardVerifier interface {
	verifyCard(context.Context, notify.Decision) error
}

// Dispatcher sends callbacks from one Telegram poller to broker Operator V1 sources.
type Dispatcher struct {
	routes map[string]OperatorSource
	cards  cardVerifier
}

var terminalDecisionAnswers = map[grants.Status]notify.Answer{
	grants.StatusActive:   notify.AnswerApproved,
	grants.StatusDenied:   notify.AnswerDenied,
	grants.StatusFailed:   notify.AnswerFailed,
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

// NewDispatcher builds the route dispatcher. cards holds the cards the owner
// sent, so that only clicks on those cards reach a broker.
func NewDispatcher(routes map[string]OperatorSource, cards cardVerifier) (*Dispatcher, error) {
	if len(routes) == 0 || cards == nil {
		return nil, errors.New("telegram dispatcher requires at least one route and the card store")
	}
	cloned := make(map[string]OperatorSource, len(routes))
	for route, source := range routes {
		if !validRoute(route) || source == nil {
			return nil, fmt.Errorf("telegram dispatcher route %q is invalid", route)
		}
		cloned[route] = source
	}
	return &Dispatcher{routes: cloned, cards: cards}, nil
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
	if err := d.cards.verifyCard(ctx, decision); errors.Is(err, errCardMismatch) {
		return notify.DecisionResult{Answer: notify.AnswerSuperseded, MessageStatus: notify.Status{Kind: notify.StatusSuperseded}}
	} else if err != nil {
		return notify.DecisionResult{Answer: notify.AnswerUnavailable}
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
	updated, err := source.Decide(ctx, current.ID, action, operatorv1.Decision{
		ExpectedRevision: current.Revision,
		IdempotencyKey:   callbackIdempotencyKey(decision),
		OnBehalfOf:       operatorActor(decision),
	})
	if err != nil {
		return dispatcherErrorResult(err)
	}
	return completedDecisionResult(updated)
}

// operatorActor returns the stable audit identity of the Telegram operator
// who clicked a card.
func operatorActor(decision notify.Decision) string {
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

func semanticApproval(request operatorv1.Request, route, token string) (Approval, error) {
	broker := routeBrokerNames[route]
	if broker == "" || request.PendingExpiresAt == nil {
		return Approval{}, errors.New("pending notification presentation is unavailable")
	}
	facts := make([]approvalview.Fact, len(request.Presentation.Facts))
	for index, fact := range request.Presentation.Facts {
		facts[index] = approvalview.Fact{Label: fact.Label, Value: fact.Value}
	}
	warnings := make([]approvalview.Warning, len(request.Presentation.Warnings))
	for index, warning := range request.Presentation.Warnings {
		warnings[index] = approvalview.Warning{Severity: approvalview.Risk(warning.Severity), Text: warning.Text}
	}
	return Approval{
		GrantID: request.ID, DecisionToken: token, Broker: broker, Requester: request.Requester,
		Operation: request.Operation, Mode: request.Mode, Reason: request.RequestReason,
		RequestedDurationSeconds: request.RequestedDurationSeconds,
		MaxUses:                  request.GrantedMaxUses, PendingExpiresAt: *request.PendingExpiresAt,
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
	return "telegram-" + logicalDecisionKey(decision)
}

func logicalDecisionKey(decision notify.Decision) string {
	tokenVerifier := sha256.Sum256([]byte(decision.DecisionToken))
	value := fmt.Sprintf("%s\x00%s\x00%d\x00%s\x00%x", decision.Route, decision.GrantID, decision.MessageID, decision.Action, tokenVerifier)
	digest := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

var terminalDispatcherFailureCodes = map[string]struct{}{
	"plan_unavailable": {}, "plan_mismatch": {},
	"credential_changed": {}, "credential_insufficient": {},
}

var closedDispatcherFailureCodes = map[string]struct{}{
	"idempotency_conflict": {}, "invalid_transition": {},
}

func dispatcherErrorResult(err error) notify.DecisionResult {
	var apiError *operatorclient.Error
	if !errors.As(err, &apiError) {
		return notify.DecisionResult{Answer: notify.AnswerUnavailable}
	}
	return dispatcherAPIErrorResult(apiError)
}

func dispatcherAPIErrorResult(apiError *operatorclient.Error) notify.DecisionResult {
	if apiError.Current != nil && apiError.Current.Status != grants.StatusPending {
		return completedDecisionResult(*apiError.Current)
	}
	if apiError.Status == 404 {
		return notify.DecisionResult{Answer: notify.AnswerNotFound, MessageStatus: notify.Status{Kind: notify.StatusUnavailable}}
	}
	if _, terminal := terminalDispatcherFailureCodes[apiError.Code]; terminal {
		return notify.DecisionResult{Answer: notify.AnswerFailed, MessageStatus: notify.Status{
			Kind: notify.StatusFailed, FailureCode: apiError.Code, FailureReference: apiError.CorrelationID,
		}}
	}
	if _, closed := closedDispatcherFailureCodes[apiError.Code]; closed {
		return notify.DecisionResult{Answer: notify.AnswerClosed, MessageStatus: notify.Status{Kind: notify.StatusClosed}}
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
	status := notify.Status{UsedCount: request.UsedCount, MaxUses: request.GrantedMaxUses,
		FailureCode: request.FailureCode, FailureReference: request.FailureReference}
	if request.Status == grants.StatusExpired {
		if request.ActiveExpiresAt == nil {
			status.Kind = notify.StatusPendingExpired
		} else {
			status.Kind = notify.StatusActiveExpired
		}
		return status
	}
	status.Kind = map[grants.Status]notify.StatusKind{
		grants.StatusActive: notify.StatusActive, grants.StatusDenied: notify.StatusDenied, grants.StatusFailed: notify.StatusFailed,
		grants.StatusConsumed: notify.StatusConsumed, grants.StatusRevoked: notify.StatusRevoked,
		grants.StatusCanceled: notify.StatusCanceled,
	}[request.Status]
	if status.Kind == notify.StatusActive && request.UsedCount > 0 {
		status.Kind = notify.StatusUsedActive
	}
	if status.Kind == "" {
		status.Kind = notify.StatusClosed
	}
	return status
}
