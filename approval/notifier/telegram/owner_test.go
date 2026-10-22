package telegram

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/approval/notifier"
	"github.com/osolmaz/unyolo/authorization/grants"
	"github.com/osolmaz/unyolo/operator/client"
	"github.com/osolmaz/unyolo/operator/v1"
)

// fakeCardSource is one broker's Operator V1 surface as the owner sees it.
type fakeCardSource struct {
	mu        sync.Mutex
	requests  map[string]operatorv1.Request
	listed    string
	events    []operatorv1.Event
	watchErr  error
	watchedAt []string
	gets      int
}

func newFakeCardSource(requests ...operatorv1.Request) *fakeCardSource {
	source := &fakeCardSource{requests: map[string]operatorv1.Request{}, listed: "cursor-0"}
	for _, request := range requests {
		source.requests[request.ID] = request
	}
	return source
}

func (s *fakeCardSource) set(request operatorv1.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[request.ID] = request
}

func (s *fakeCardSource) Get(_ context.Context, id string) (operatorv1.Request, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	request, ok := s.requests[id]
	if !ok {
		return operatorv1.Request{}, &operatorclient.Error{Status: http.StatusNotFound, Code: "not_found"}
	}
	return request, nil
}

func (s *fakeCardSource) Decide(context.Context, string, operatorv1.Action, operatorv1.Decision) (operatorv1.Request, error) {
	return operatorv1.Request{}, errors.New("not used by the owner")
}

func (s *fakeCardSource) List(_ context.Context, query operatorv1.Query) (operatorv1.Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	page := operatorv1.Page{EventCursor: s.listed}
	for _, request := range s.requests {
		if request.Status == grants.StatusPending && query.Status == grants.StatusGroupPending {
			page.Requests = append(page.Requests, request)
		}
	}
	return page, nil
}

func (s *fakeCardSource) Watch(_ context.Context, cursor string) (operatorv1.EventStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.watchedAt = append(s.watchedAt, cursor)
	if s.watchErr != nil {
		return nil, s.watchErr
	}
	events := s.events
	s.events = nil
	return &fakeEventStream{events: events}, nil
}

type fakeEventStream struct {
	events []operatorv1.Event
}

func (s *fakeEventStream) Receive(context.Context) (operatorv1.Event, error) {
	if len(s.events) == 0 {
		return operatorv1.Event{}, io.EOF
	}
	event := s.events[0]
	s.events = s.events[1:]
	return event, nil
}

func (s *fakeEventStream) Close() error { return nil }

// telegramRecorder is a fake Bot API that records each method and payload.
type telegramRecorder struct {
	mu        sync.Mutex
	calls     []recordedCall
	messageID int
}

type recordedCall struct {
	method  string
	payload map[string]any
}

func (r *telegramRecorder) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		payload := decodePayload(t, request)
		r.mu.Lock()
		r.calls = append(r.calls, recordedCall{method: path.Base(request.URL.Path), payload: payload})
		r.messageID++
		messageID := 100 + r.messageID
		r.mu.Unlock()
		if strings.HasSuffix(request.URL.Path, "/sendMessage") {
			writeMessage(w, messageID)
			return
		}
		writeOK(w)
	})
}

func (r *telegramRecorder) methods() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	methods := make([]string, len(r.calls))
	for index, call := range r.calls {
		methods[index] = call.method
	}
	return methods
}

func (r *telegramRecorder) last() recordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[len(r.calls)-1]
}

func newTestOwner(t *testing.T, inbox *Inbox, routes map[string]CardSource) (*Owner, *telegramRecorder) {
	t.Helper()
	recorder := &telegramRecorder{}
	server := httptest.NewServer(recorder.handler(t))
	t.Cleanup(server.Close)
	client, err := New("test-token", 123, server.Client(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewOwner(client, inbox, routes)
	if err != nil {
		t.Fatal(err)
	}
	owner.retryDelay = time.Millisecond
	return owner, recorder
}

func openTestInbox(t *testing.T) *Inbox {
	t.Helper()
	inbox, err := OpenInbox(t.Context(), filepath.Join(t.TempDir(), "callbacks.db"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inbox.Close() })
	return inbox
}

func requestWithStatus(id string, status grants.Status) operatorv1.Request {
	request := pendingOperatorRequest()
	request.ID, request.Status = id, status
	return request
}

func TestOwnerSendsNoCardForRequestDecidedBeforeItWasListed(t *testing.T) {
	inbox := openTestInbox(t)
	source := newFakeCardSource(requestWithStatus("grant-1", grants.StatusActive))
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	source.events = []operatorv1.Event{{Cursor: "cursor-1", Kind: "request.approved", RequestID: "grant-1"}}
	if err := owner.follow(t.Context(), RouteGitHub, source); !errors.Is(err, io.EOF) {
		t.Fatalf("follow() error = %v, want end of stream", err)
	}
	if methods := recorder.methods(); len(methods) != 0 {
		t.Fatalf("Telegram calls = %v, want none for a request that was never pending here", methods)
	}
	if cursor, _ := inbox.eventCursor(t.Context(), RouteGitHub); cursor != "cursor-1" {
		t.Fatalf("cursor = %q, want cursor-1", cursor)
	}
}

func TestOwnerCardLifecycle(t *testing.T) {
	inbox := openTestInbox(t)
	source := newFakeCardSource(requestWithStatus("grant-1", grants.StatusPending))
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})

	if err := owner.follow(t.Context(), RouteGitHub, source); !errors.Is(err, io.EOF) {
		t.Fatalf("first follow() error = %v", err)
	}
	sent := recorder.last()
	keyboard := sent.payload["reply_markup"].(map[string]any)["inline_keyboard"].([]any)[0].([]any)
	approve := keyboard[0].(map[string]any)
	if sent.method != "sendMessage" || approve["text"] != approveButtonText || !strings.HasPrefix(approve["callback_data"].(string), "bk:g:a:") {
		t.Fatalf("card = %+v", sent)
	}
	stored, found, err := inbox.card(t.Context(), RouteGitHub, "grant-1")
	if err != nil || !found || stored.State != cardOpen || stored.MessageID != 101 || stored.ChatID != 123 {
		t.Fatalf("stored card = %+v, %v, %v", stored, found, err)
	}
	if cursor, err := inbox.eventCursor(t.Context(), RouteGitHub); err != nil || cursor != "cursor-0" {
		t.Fatalf("cursor = %q, %v", cursor, err)
	}

	source.set(requestWithStatus("grant-1", grants.StatusActive))
	source.events = []operatorv1.Event{{Cursor: "cursor-1", RequestID: "grant-1"}}
	if err := owner.follow(t.Context(), RouteGitHub, source); !errors.Is(err, io.EOF) {
		t.Fatalf("second follow() error = %v", err)
	}
	if source.watchedAt[1] != "cursor-0" || recorder.last().method != "editMessageText" ||
		!strings.Contains(recorder.last().payload["text"].(string), "Approved") {
		t.Fatalf("approved edit = %+v watched=%v", recorder.last(), source.watchedAt)
	}
	if stored, _, _ := inbox.card(t.Context(), RouteGitHub, "grant-1"); stored.State != cardOpen {
		t.Fatalf("active card state = %q, want open for later usage updates", stored.State)
	}

	source.set(requestWithStatus("grant-1", grants.StatusConsumed))
	source.events = []operatorv1.Event{{Cursor: "cursor-2", RequestID: "grant-1"}}
	_ = owner.follow(t.Context(), RouteGitHub, source)
	if stored, _, _ := inbox.card(t.Context(), RouteGitHub, "grant-1"); stored.State != cardClosed {
		t.Fatalf("consumed card state = %q, want closed", stored.State)
	}
	if cursor, _ := inbox.eventCursor(t.Context(), RouteGitHub); cursor != "cursor-2" {
		t.Fatalf("cursor = %q, want cursor-2", cursor)
	}
}

func TestOwnerRestartDoesNotSendDuplicateCards(t *testing.T) {
	inbox := openTestInbox(t)
	source := newFakeCardSource(requestWithStatus("grant-1", grants.StatusPending))
	first, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	_ = first.follow(t.Context(), RouteGitHub, source)
	if err := inbox.clearEventCursor(t.Context(), RouteGitHub); err != nil {
		t.Fatal(err)
	}
	second, _ := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	second.client = first.client
	_ = second.follow(t.Context(), RouteGitHub, source)
	if methods := strings.Join(recorder.methods(), ","); methods != "sendMessage" {
		t.Fatalf("Telegram calls after restart = %s, want one card", methods)
	}
}

func TestOwnerResendsCardInterruptedBeforeTelegramConfirmed(t *testing.T) {
	inbox := openTestInbox(t)
	if _, err := inbox.reserveCard(t.Context(), RouteGitHub, "grant-1", "old-token", "old text"); err != nil {
		t.Fatal(err)
	}
	source := newFakeCardSource(requestWithStatus("grant-1", grants.StatusPending))
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	_ = owner.follow(t.Context(), RouteGitHub, source)
	stored, _, _ := inbox.card(t.Context(), RouteGitHub, "grant-1")
	if strings.Join(recorder.methods(), ",") != "sendMessage" || stored.State != cardOpen || bytes.Equal(stored.TokenDigest, tokenDigest("old-token")) {
		t.Fatalf("resent card = %+v calls=%v", stored, recorder.methods())
	}
}

func TestOwnerResyncsAfterExpiredCursor(t *testing.T) {
	inbox := openTestInbox(t)
	if err := inbox.saveEventCursor(t.Context(), RouteGitHub, "old"); err != nil {
		t.Fatal(err)
	}
	source := newFakeCardSource()
	source.watchErr = &operatorclient.Error{Status: http.StatusGone, Code: "cursor_expired"}
	owner, _ := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	if err := owner.follow(t.Context(), RouteGitHub, source); err != nil {
		t.Fatalf("follow() with an expired cursor error = %v, want resync on the next pass", err)
	}
	if cursor, _ := inbox.eventCursor(t.Context(), RouteGitHub); cursor != "" {
		t.Fatalf("expired cursor kept: %q", cursor)
	}
	source.watchErr = nil
	_ = owner.follow(t.Context(), RouteGitHub, source)
	if strings.Join(source.watchedAt, ",") != "old,cursor-0" {
		t.Fatalf("watched cursors = %v", source.watchedAt)
	}
}

func TestOwnerClosesCardsOfMissingRequests(t *testing.T) {
	inbox := openTestInbox(t)
	source := newFakeCardSource(requestWithStatus("grant-1", grants.StatusPending))
	owner, recorder := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: source})
	_ = owner.follow(t.Context(), RouteGitHub, source)
	source.mu.Lock()
	delete(source.requests, "grant-1")
	source.mu.Unlock()
	if err := owner.apply(t.Context(), RouteGitHub, source, "grant-1"); err != nil {
		t.Fatal(err)
	}
	if stored, _, _ := inbox.card(t.Context(), RouteGitHub, "grant-1"); stored.State != cardClosed || recorder.last().method != "editMessageText" {
		t.Fatalf("missing request card = %+v last=%+v", stored, recorder.last())
	}
	if err := owner.apply(t.Context(), RouteGitHub, source, "never-sent"); err != nil {
		t.Fatalf("apply() for a request without a card error = %v", err)
	}
}

func TestOwnerRunStopsWithContextAndRetriesFailingRoutes(t *testing.T) {
	inbox := openTestInbox(t)
	failing := newFakeCardSource()
	failing.watchErr = errors.New("offline")
	owner, _ := newTestOwner(t, inbox, map[string]CardSource{RouteGitHub: failing, RouteSudo: newFakeCardSource()})
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if err := owner.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v", err)
	}
	failing.mu.Lock()
	attempts := len(failing.watchedAt)
	failing.mu.Unlock()
	if attempts < 2 {
		t.Fatalf("failing route watch attempts = %d, want retries", attempts)
	}
}

func TestNewOwnerValidation(t *testing.T) {
	inbox := openTestInbox(t)
	client, err := New("test-token", 123, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for name, routes := range map[string]map[string]CardSource{
		"no routes":     nil,
		"unknown route": {"x": newFakeCardSource()},
		"nil source":    {RouteGitHub: nil},
	} {
		if _, err := NewOwner(client, inbox, routes); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if _, err := NewOwner(nil, inbox, map[string]CardSource{RouteGitHub: newFakeCardSource()}); err == nil {
		t.Fatal("owner without a client accepted")
	}
	if !finalStatus(grants.StatusDenied) || finalStatus(grants.StatusActive) || finalStatus(grants.StatusPending) {
		t.Fatal("finalStatus() classification is wrong")
	}
	if token, err := newCardToken(); err != nil || len(token) != 16 {
		t.Fatalf("newCardToken() = %q, %v", token, err)
	}
}

func TestVerifyCardRequiresTheOwnersOpenCard(t *testing.T) {
	inbox := openTestInbox(t)
	if _, err := inbox.reserveCard(t.Context(), RouteGitHub, "grant-1", "token-1", "text"); err != nil {
		t.Fatal(err)
	}
	valid := notify.Decision{Route: RouteGitHub, GrantID: "grant-1", DecisionToken: "token-1", ChatID: 123, MessageID: 9,
		Action: notify.ActionApprove, ButtonText: approveButtonText}
	if err := inbox.verifyCard(t.Context(), valid); !errors.Is(err, errCardMismatch) {
		t.Fatalf("verifyCard() on an unconfirmed card = %v", err)
	}
	if err := inbox.openCard(t.Context(), RouteGitHub, "grant-1", 123, 9); err != nil {
		t.Fatal(err)
	}
	if err := inbox.verifyCard(t.Context(), valid); err != nil {
		t.Fatalf("verifyCard() = %v", err)
	}
	for name, change := range map[string]func(*notify.Decision){
		"other token":   func(d *notify.Decision) { d.DecisionToken = "token-2" },
		"other message": func(d *notify.Decision) { d.MessageID = 10 },
		"other chat":    func(d *notify.Decision) { d.ChatID = 124 },
		"swapped label": func(d *notify.Decision) { d.ButtonText = denyButtonText },
		"other request": func(d *notify.Decision) { d.GrantID = "grant-2" },
		"other route":   func(d *notify.Decision) { d.Route = RouteSudo },
	} {
		decision := valid
		change(&decision)
		if err := inbox.verifyCard(t.Context(), decision); !errors.Is(err, errCardMismatch) {
			t.Fatalf("%s: verifyCard() = %v, want mismatch", name, err)
		}
	}
	if reserved, err := inbox.reserveCard(t.Context(), RouteGitHub, "grant-1", "token-3", "text"); err != nil || reserved {
		t.Fatalf("reserveCard() over an open card = %t, %v", reserved, err)
	}
}

func TestPressedButtonTextReadsTheClickedButton(t *testing.T) {
	message := &telegramMessage{ReplyMarkup: &telegramInlineMarkup{InlineKeyboard: [][]telegramInlineButton{{
		{Text: approveButtonText, CallbackData: "approve-data"}, {Text: denyButtonText, CallbackData: "deny-data"},
	}}}}
	if message.pressedButtonText("deny-data") != denyButtonText || message.pressedButtonText("other") != "" {
		t.Fatal("pressedButtonText() picked the wrong button")
	}
	if (&telegramMessage{}).pressedButtonText("deny-data") != "" {
		t.Fatal("pressedButtonText() without a keyboard returned a label")
	}
	if buttonText(notify.Action("other")) != "" {
		t.Fatal("buttonText() returned a label for an unknown action")
	}
}
