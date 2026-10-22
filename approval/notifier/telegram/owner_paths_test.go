package telegram

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/approval/view"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/operator/v1"
)

// failingSource overrides one fakeCardSource call with an error.
type failingSource struct {
	*fakeCardSource
	listErr error
	getErr  error
	page    *operatorv1.Page
}

func (s *failingSource) List(ctx context.Context, query operatorv1.Query) (operatorv1.Page, error) {
	if s.listErr != nil {
		return operatorv1.Page{}, s.listErr
	}
	if s.page != nil {
		return *s.page, nil
	}
	return s.fakeCardSource.List(ctx, query)
}

func (s *failingSource) Get(ctx context.Context, id string) (operatorv1.Request, error) {
	if s.getErr != nil {
		return operatorv1.Request{}, s.getErr
	}
	return s.fakeCardSource.Get(ctx, id)
}

// pagedSource returns its pending requests one page at a time.
type pagedSource struct {
	*fakeCardSource
	queries []operatorv1.Query
}

func (s *pagedSource) List(_ context.Context, query operatorv1.Query) (operatorv1.Page, error) {
	s.queries = append(s.queries, query)
	if query.Cursor == "" {
		return operatorv1.Page{Requests: []operatorv1.Request{requestWithStatus("grant-1", grants.StatusPending)},
			NextCursor: "page-2", EventCursor: "cursor-first"}, nil
	}
	return operatorv1.Page{Requests: []operatorv1.Request{requestWithStatus("grant-2", grants.StatusPending)},
		EventCursor: "cursor-later"}, nil
}

func TestOwnerResyncReadsEveryPageAndKeepsTheFirstCursor(t *testing.T) {
	inbox := openTestInbox(t)
	source := &pagedSource{fakeCardSource: newFakeCardSource(
		requestWithStatus("grant-1", grants.StatusPending), requestWithStatus("grant-2", grants.StatusPending))}
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	cursor, err := owner.resync(t.Context(), RouteGitHub, source)
	if err != nil || cursor != "cursor-first" || len(source.queries) != 2 || source.queries[1].Cursor != "page-2" {
		t.Fatalf("resync() = %q, %v queries=%+v", cursor, err, source.queries)
	}
	if methods := strings.Join(recorder.methods(), ","); methods != "sendMessage,sendMessage" {
		t.Fatalf("Telegram calls = %s, want a card per page", methods)
	}
}

func TestOwnerFollowReportsSourceAndStoreFailures(t *testing.T) {
	offline := errors.New("offline")
	tests := map[string]func(*testing.T) (*Owner, CardSource){
		"list": func(t *testing.T) (*Owner, CardSource) {
			source := &failingSource{fakeCardSource: newFakeCardSource(), listErr: offline}
			owner, _ := newTestOwner(t, openTestInbox(t), map[string]CardSource{RouteGitHub: source})
			return owner, source
		},
		"missing event cursor": func(t *testing.T) (*Owner, CardSource) {
			source := &failingSource{fakeCardSource: newFakeCardSource(), page: &operatorv1.Page{}}
			owner, _ := newTestOwner(t, openTestInbox(t), map[string]CardSource{RouteGitHub: source})
			return owner, source
		},
		"watch": func(t *testing.T) (*Owner, CardSource) {
			source := newFakeCardSource()
			source.watchErr = offline
			owner, _ := newTestOwner(t, openTestInbox(t), map[string]CardSource{RouteGitHub: source})
			return owner, source
		},
		"event read": func(t *testing.T) (*Owner, CardSource) {
			source := &failingSource{fakeCardSource: newFakeCardSource(), getErr: offline}
			source.events = []operatorv1.Event{{Cursor: "cursor-1", RequestID: "grant-1"}}
			owner, _ := newTestOwner(t, openTestInbox(t), map[string]CardSource{RouteGitHub: source})
			return owner, source
		},
		"closed store": func(t *testing.T) (*Owner, CardSource) {
			inbox := openTestInbox(t)
			source := newFakeCardSource()
			owner, _ := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
			_ = inbox.Close()
			return owner, source
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			owner, source := build(t)
			if err := owner.follow(t.Context(), RouteGitHub, source); err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("follow() error = %v, want a failure", err)
			}
		})
	}
}

func TestOwnerSendFailuresLeaveTheCardRetryable(t *testing.T) {
	inbox := openTestInbox(t)
	source := newFakeCardSource()
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	request := requestWithStatus("grant-1", grants.StatusPending)

	owner.newToken = func() (string, error) { return "", errors.New("no entropy") }
	if err := owner.applyRequest(t.Context(), RouteGitHub, request); err == nil {
		t.Fatal("send without a token succeeded")
	}
	owner.newToken = newCardToken
	withoutExpiry := request
	withoutExpiry.PendingExpiresAt = nil
	if err := owner.applyRequest(t.Context(), RouteGitHub, withoutExpiry); err == nil {
		t.Fatal("send without a pending expiry succeeded")
	}
	unrenderable := request
	unrenderable.Presentation.Title = ""
	if err := owner.applyRequest(t.Context(), RouteGitHub, unrenderable); err == nil {
		t.Fatal("send of an unrenderable request succeeded")
	}
	if methods := recorder.methods(); len(methods) != 0 {
		t.Fatalf("Telegram calls = %v, want none", methods)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer failing.Close()
	if owner.client, _ = New("test-token", 123, failing.Client(), failing.URL); owner.applyRequest(t.Context(), RouteGitHub, request) == nil {
		t.Fatal("send through an unavailable Telegram succeeded")
	}
	stored, found, err := inbox.card(t.Context(), RouteGitHub, "grant-1")
	if err != nil || !found || stored.State != cardSending {
		t.Fatalf("card after failed send = %+v, %v, %v; want sending for a retry", stored, found, err)
	}
}

func TestOwnerClosesUnconfirmedCardsOfDecidedRequests(t *testing.T) {
	inbox := openTestInbox(t)
	if _, err := inbox.reserveCard(t.Context(), RouteGitHub, "grant-1", "token", "text"); err != nil {
		t.Fatal(err)
	}
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: newFakeCardSource()})
	if err := owner.applyRequest(t.Context(), RouteGitHub, requestWithStatus("grant-1", grants.StatusDenied)); err != nil {
		t.Fatal(err)
	}
	if err := owner.applyRequest(t.Context(), RouteGitHub, requestWithStatus("grant-1", grants.StatusDenied)); err != nil {
		t.Fatal(err)
	}
	if stored, _, _ := inbox.card(t.Context(), RouteGitHub, "grant-1"); stored.State != cardClosed || len(recorder.methods()) != 0 {
		t.Fatalf("unconfirmed card = %+v calls=%v, want closed without an edit", stored, recorder.methods())
	}
	if err := owner.closeMissing(t.Context(), RouteGitHub, "grant-1"); err != nil {
		t.Fatalf("closeMissing() on a closed card = %v", err)
	}
}

func TestOwnerReportsCardEditFailures(t *testing.T) {
	inbox := openTestInbox(t)
	if _, err := inbox.reserveCard(t.Context(), RouteGitHub, "grant-1", "token", "text"); err != nil {
		t.Fatal(err)
	}
	if err := inbox.openCard(t.Context(), RouteGitHub, "grant-1", 123, 9); err != nil {
		t.Fatal(err)
	}
	owner, _ := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: newFakeCardSource()})
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer failing.Close()
	owner.client, _ = New("test-token", 123, failing.Client(), failing.URL)
	if err := owner.applyRequest(t.Context(), RouteGitHub, requestWithStatus("grant-1", grants.StatusDenied)); err == nil {
		t.Fatal("failed edit was reported as delivered")
	}
	if stored, _, _ := inbox.card(t.Context(), RouteGitHub, "grant-1"); stored.State != cardOpen {
		t.Fatalf("card after failed edit = %+v, want open for a retry", stored)
	}
}

func TestVerifyCardReportsStoreFailures(t *testing.T) {
	inbox := openTestInbox(t)
	_ = inbox.Close()
	err := inbox.verifyCard(t.Context(), notify.Decision{Route: RouteGitHub, GrantID: "grant-1"})
	if err == nil || errors.Is(err, errCardMismatch) {
		t.Fatalf("verifyCard() on a closed store = %v, want a store error", err)
	}
}

func TestOperatorActorIdentities(t *testing.T) {
	for want, decision := range map[string]notify.Decision{
		"telegram:42":     {OperatorID: 42, OperatorTag: "tag"},
		"telegram:@tag":   {OperatorTag: "tag", Approver: "named"},
		"named":           {Approver: "named"},
		"telegram":        {},
		"telegram:-10042": {OperatorID: -10042},
	} {
		if got := operatorActor(decision); got != want {
			t.Fatalf("operatorActor(%+v) = %q, want %q", decision, got, want)
		}
	}
}

func TestStatusForRequestCoversCardStates(t *testing.T) {
	expires := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	for want, request := range map[notify.StatusKind]operatorv1.Request{
		notify.StatusPendingExpired: {Status: grants.StatusExpired},
		notify.StatusActiveExpired:  {Status: grants.StatusExpired, ActiveExpiresAt: &expires},
		notify.StatusActive:         {Status: grants.StatusActive},
		notify.StatusUsedActive:     {Status: grants.StatusActive, UsedCount: 1, GrantedMaxUses: usebudget.Limit(3)},
		notify.StatusFailed:         {Status: grants.StatusFailed, FailureCode: "plan_mismatch"},
		notify.StatusClosed:         {Status: grants.Status("unknown")},
	} {
		if got := statusForRequest(request); got.Kind != want {
			t.Fatalf("statusForRequest(%+v) = %+v, want %s", request, got, want)
		}
	}
	if _, ok := operatorAction(notify.Action("unknown")); ok {
		t.Fatal("unknown action mapped to an operator action")
	}
}

func TestDispatcherIgnoresUnknownActions(t *testing.T) {
	source := &dispatcherSource{request: pendingOperatorRequest()}
	dispatcher, err := NewDispatcher(map[string]OperatorSource{RouteGitHub: source}, acceptCards{})
	if err != nil {
		t.Fatal(err)
	}
	result := dispatcher.Handle(t.Context(), notify.Decision{Route: RouteGitHub, GrantID: "grant-1", Action: notify.Action("unknown")})
	if result.Answer != notify.AnswerIgnored || source.decideCall != 0 {
		t.Fatalf("Handle(unknown action) = %+v calls=%d", result, source.decideCall)
	}
	source.decideErr = errors.New("offline")
	result = dispatcher.Handle(t.Context(), notify.Decision{Route: RouteGitHub, GrantID: "grant-1", Action: notify.ActionApprove})
	if result.Answer != notify.AnswerUnavailable {
		t.Fatalf("Handle(decide failure) = %+v", result)
	}
}

func TestRenderedCardsOmitARepeatedPlanHash(t *testing.T) {
	approval := validApproval()
	approval.Presentation.PlanHash = "sha256:" + strings.Repeat("a", 64)
	withHash, err := RenderApproval(approval)
	if err != nil || !strings.Contains(withHash, strings.Repeat("a", 12)) {
		t.Fatalf("RenderApproval(plan hash) = %q, %v", withHash, err)
	}
	approval.Presentation.Facts = []approvalview.Fact{{Label: "Plan hash", Value: "listed"}}
	listed, err := RenderApproval(approval)
	if err != nil || strings.Contains(listed, strings.Repeat("a", 12)) {
		t.Fatalf("RenderApproval(listed plan hash) = %q, %v", listed, err)
	}
}

func TestClickResultsRenderFromTheStoredCard(t *testing.T) {
	inbox := openTestInbox(t)
	if _, err := inbox.reserveCard(t.Context(), RouteGitHub, "grant-1", "token", "<b>Stored card</b>"); err != nil {
		t.Fatal(err)
	}
	click := notify.Decision{Route: RouteGitHub, GrantID: "grant-1", ChatID: 123, MessageID: 9, MessageText: "Plain <text>"}
	if text, err := inbox.cardText(t.Context(), click); err != nil || text != "Plain &lt;text&gt;" {
		t.Fatalf("cardText(unconfirmed card) = %q, %v", text, err)
	}
	if err := inbox.openCard(t.Context(), RouteGitHub, "grant-1", 123, 9); err != nil {
		t.Fatal(err)
	}
	if text, err := inbox.cardText(t.Context(), click); err != nil || text != "<b>Stored card</b>" {
		t.Fatalf("cardText(open card) = %q, %v", text, err)
	}
	other := click
	other.MessageID = 10
	if text, err := inbox.cardText(t.Context(), other); err != nil || text != "Plain &lt;text&gt;" {
		t.Fatalf("cardText(other message) = %q, %v", text, err)
	}

	recorder := &telegramRecorder{}
	server := httptest.NewServer(recorder.handler(t))
	defer server.Close()
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	result := notify.DecisionResult{Answer: notify.AnswerApproved, MessageStatus: notify.Status{Kind: notify.StatusActive}}
	if err := client.finishDurableDecision(t.Context(), inbox, click, result); err != nil {
		t.Fatal(err)
	}
	if edit := recorder.last(); edit.method != "editMessageText" || !strings.HasPrefix(edit.payload["text"].(string), "<b>Stored card</b>") {
		t.Fatalf("click edit = %+v, want the stored card text", edit)
	}
	if err := client.finishDurableDecision(t.Context(), inbox, click, notify.DecisionResult{Answer: notify.AnswerIgnored}); err != nil {
		t.Fatalf("finishDurableDecision(no status) = %v", err)
	}
	_ = inbox.Close()
	if err := client.finishDurableDecision(t.Context(), inbox, click, result); err == nil {
		t.Fatal("finishDurableDecision() with a closed store succeeded")
	}
}
