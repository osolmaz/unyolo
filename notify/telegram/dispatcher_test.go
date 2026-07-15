package telegram

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/grants"
	"github.com/osolmaz/brokerkit/notify"
	"github.com/osolmaz/brokerkit/operatorclient"
	"github.com/osolmaz/brokerkit/operatorv1"
)

type dispatcherSource struct {
	request    operatorv1.Request
	getErr     error
	decideErr  error
	decision   operatorv1.Decision
	action     operatorv1.Action
	decideCall int
}

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
	source := &dispatcherSource{request: operatorv1.Request{ID: "grant-1", Revision: 3, Status: grants.StatusPending}}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteHuggingFace: source})
	if err != nil {
		t.Fatal(err)
	}
	decision := notify.Decision{Route: RouteHuggingFace, Action: notify.ActionApprove, GrantID: "grant-1",
		DecisionToken: "token", CallbackID: "callback", OperatorID: 42}
	result := dispatcher.Handle(t.Context(), decision)
	if result.Answer != "Grant approved" || !result.ClearButtons || result.Retry || source.decideCall != 1 {
		t.Fatalf("Handle() = %+v calls=%d", result, source.decideCall)
	}
	if source.action != operatorv1.ActionApprove || source.decision.ExpectedRevision != 3 ||
		source.decision.OnBehalfOf != "telegram:42" || !strings.HasPrefix(source.decision.IdempotencyKey, "telegram-") {
		t.Fatalf("operator decision = %+v action=%q", source.decision, source.action)
	}
}

func TestDispatcherHandlesTerminalAndUnavailableRoutes(t *testing.T) {
	terminal := &dispatcherSource{request: operatorv1.Request{ID: "grant-1", Status: grants.StatusDenied}}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteGitHub: terminal})
	if err != nil {
		t.Fatal(err)
	}
	result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteGitHub, GrantID: "grant-1"})
	if result.Answer != "Grant denied" || !result.ClearButtons || terminal.decideCall != 0 {
		t.Fatalf("terminal Handle() = %+v calls=%d", result, terminal.decideCall)
	}
	result = dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo, GrantID: "grant-1"})
	if result.Answer != "Approval route is unavailable" || !result.ClearButtons {
		t.Fatalf("missing route Handle() = %+v", result)
	}
}

func TestDispatcherRetriesTransientOperatorFailure(t *testing.T) {
	source := &dispatcherSource{getErr: errors.New("offline")}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteSudo: source})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo}); !result.Retry {
		t.Fatalf("Handle() = %+v, want retry", result)
	}
	source.getErr = &operatorclient.Error{Status: 404, Code: "not_found"}
	if result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteSudo}); result.Answer != "Grant not found" || !result.ClearButtons {
		t.Fatalf("not-found Handle() = %+v", result)
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
