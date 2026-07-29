package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/operator/client"
	"github.com/osolmaz/unyolo/operator/v1"
	"github.com/osolmaz/unyolo/protocol/contract"
)

type dispatcherSource struct {
	request    operatorv1.Request
	getErr     error
	decideErr  error
	decision   operatorv1.Decision
	action     operatorv1.Action
	decideCall int
	descriptor *operatorv1.Descriptor
}

func (s *dispatcherSource) Discover(context.Context) (operatorv1.Descriptor, error) {
	if s.descriptor != nil {
		return *s.descriptor, nil
	}
	return operatorv1.Descriptor{APIVersion: operatorv1.APIVersion, ContractDigest: contract.OperatorV1Digest, BuildID: "test"}, nil
}

func (s *dispatcherSource) Health(context.Context) error { return nil }

func (s *dispatcherSource) Get(context.Context, string) (operatorv1.Request, error) {
	return s.request, s.getErr
}

func (s *dispatcherSource) Decide(_ context.Context, _ string, action operatorv1.Action, decision operatorv1.Decision) (operatorv1.Request, error) {
	s.decideCall++
	s.action, s.decision = action, decision
	if s.decideErr != nil {
		return operatorv1.Request{}, s.decideErr
	}
	s.request.Status = grants.StatusActive
	if action == operatorv1.ActionDeny {
		s.request.Status = grants.StatusDenied
	}
	return s.request, nil
}

func TestDispatcherRoutesDecisionThroughOperatorSource(t *testing.T) {
	source := &dispatcherSource{request: pendingOperatorRequest()}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteHuggingFace: source})
	if err != nil {
		t.Fatal(err)
	}
	decision := notify.Decision{Route: RouteHuggingFace, Action: notify.ActionApprove, GrantID: "grant-1",
		DecisionToken: "token", CallbackID: "callback", ChatID: 7, MessageID: 8, MessageText: "approval", OperatorID: 42}
	result := dispatcher.Handle(t.Context(), decision)
	if result.Answer != notify.AnswerApproved || result.MessageStatus.Kind != notify.StatusActive || result.Retry || source.decideCall != 1 {
		t.Fatalf("Handle() = %+v calls=%d", result, source.decideCall)
	}
	if source.action != operatorv1.ActionApprove || source.decision.ExpectedRevision != 3 ||
		source.decision.OnBehalfOf != "telegram:42" || !strings.HasPrefix(source.decision.IdempotencyKey, "telegram-") ||
		source.decision.Notification == nil || source.decision.Notification.DecisionToken != "token" || source.decision.Notification.MessageID != 8 ||
		source.decision.Notification.Renderer != rendererID || source.decision.Notification.PresentationJSON == "" ||
		source.decision.Notification.PresentationDigest == "" || source.decision.Notification.RenderedDigest == "" {
		t.Fatalf("operator decision = %+v action=%q", source.decision, source.action)
	}
}

func pendingOperatorRequest() operatorv1.Request {
	expires := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	return operatorv1.Request{
		ID: "grant-1", Revision: 3, Requester: "agent-a", Operation: "repo.delete", Mode: "execution", Status: grants.StatusPending,
		PendingExpiresAt: &expires, RequestedDurationSeconds: 300, GrantedMaxUses: 1, RequestReason: "cleanup",
		Presentation: operatorv1.Presentation{Risk: "critical", Title: "Delete repository", Target: "example/project"},
	}
}

func TestDispatcherHandlesTerminalAndUnavailableRoutes(t *testing.T) {
	terminal := &dispatcherSource{request: operatorv1.Request{ID: "grant-1", Status: grants.StatusDenied}}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteGitHub: terminal})
	if err != nil {
		t.Fatal(err)
	}
	result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteGitHub, GrantID: "grant-1"})
	if result.Answer != notify.AnswerDenied || result.MessageStatus.Kind != notify.StatusDenied || terminal.decideCall != 0 {
		t.Fatalf("terminal Handle() = %+v calls=%d", result, terminal.decideCall)
	}
	result = dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo, GrantID: "grant-1"})
	if result.Answer != notify.AnswerRouteUnavailable || result.MessageStatus.Kind != notify.StatusClosed {
		t.Fatalf("missing route Handle() = %+v", result)
	}
}

func TestDispatcherDoesNotBlockSharedPollerOnTransientOperatorFailure(t *testing.T) {
	source := &dispatcherSource{getErr: errors.New("offline")}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteSudo: source})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo}); result.Retry || result.Answer != notify.AnswerUnavailable {
		t.Fatalf("Handle() = %+v, want retryable operator answer without offset retry", result)
	}
	source.getErr = &operatorclient.Error{Status: 404, Code: "not_found"}
	if result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo}); result.Answer != notify.AnswerNotFound || result.MessageStatus.Kind != notify.StatusUnavailable {
		t.Fatalf("not-found Handle() = %+v", result)
	}
	source.getErr = &operatorclient.Error{Status: 409, Code: "invalid_decision_token"}
	if result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo}); result.Answer != notify.AnswerSuperseded || result.MessageStatus.Kind != notify.StatusSuperseded {
		t.Fatalf("stale-token Handle() = %+v", result)
	}
}

func TestNewDispatcherRejectsInvalidRoutes(t *testing.T) {
	if _, err := NewDispatcher(nil); err == nil {
		t.Fatal("empty dispatcher routes accepted")
	}
	if _, err := NewDispatcher(map[string]OperatorSource{"github": &dispatcherSource{}}); err == nil {
		t.Fatal("invalid dispatcher route accepted")
	}
}

func TestDispatcherReadinessRequiresExactOperatorSource(t *testing.T) {
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteGitHub: &dispatcherSource{}})
	if err != nil || dispatcher.Ready(t.Context()) != nil {
		t.Fatalf("Ready() = %v, constructor = %v", dispatcher.Ready(t.Context()), err)
	}
	withoutReadiness, err := NewDispatcher(map[string]OperatorSource{RouteGitHub: struct{ OperatorSource }{&minimalSource{}}})
	if err != nil || withoutReadiness.Ready(t.Context()) == nil {
		t.Fatal("Ready() accepted a source without discovery and health")
	}
	wrong := &dispatcherSource{descriptor: &operatorv1.Descriptor{APIVersion: operatorv1.APIVersion,
		ContractDigest: "sha256:" + strings.Repeat("f", 64), BuildID: "test"}}
	incompatible, err := NewDispatcher(map[string]OperatorSource{RouteGitHub: wrong})
	if err != nil || incompatible.Ready(t.Context()) == nil || incompatible.Compatible(t.Context()) == nil {
		t.Fatal("dispatcher accepted a different Operator contract")
	}
}

type minimalSource struct{}

func (*minimalSource) Get(context.Context, string) (operatorv1.Request, error) {
	return operatorv1.Request{}, nil
}

func (*minimalSource) Decide(context.Context, string, operatorv1.Action, operatorv1.Decision) (operatorv1.Request, error) {
	return operatorv1.Request{}, nil
}
