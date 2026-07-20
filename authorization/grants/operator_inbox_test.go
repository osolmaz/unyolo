package grants

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/authorization/policy"
)

func TestQueryGrantsPaginatesDeterministically(t *testing.T) {
	now := time.Date(2026, 7, 11, 1, 2, 3, 0, time.UTC)
	ids := []string{"grant-a", "token-a", "grant-c", "token-c", "grant-b", "token-b"}
	store := newDeterministicStore(t, func() time.Time { return now }, &ids)
	for _, requestID := range []string{"a", "c", "b"} {
		request := testOperatorRequest(requestID)
		if _, _, err := store.Request(request); err != nil {
			t.Fatal(err)
		}
	}

	first, err := store.QueryGrants(Query{StatusGroup: StatusGroupPending, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Grants) != 2 || first.Grants[0].ID != "grant-c" || first.Grants[1].ID != "grant-b" || !first.HasMore {
		t.Fatalf("first page = %+v, want grant-c and grant-b", first)
	}
	second, err := store.QueryGrants(Query{StatusGroup: StatusGroupPending, Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Grants) != 1 || second.Grants[0].ID != "grant-a" || second.HasMore {
		t.Fatalf("second page = %+v, want grant-a", second)
	}
	if _, err := store.QueryGrants(Query{Cursor: "not-a-cursor"}); !errors.Is(err, ErrInvalidGrantCursor) {
		t.Fatalf("invalid cursor error = %v", err)
	}
}

func TestOperatorDecisionsCheckRevisionAndOnlyNarrowApproval(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{})
	result, _, err := store.Request(testOperatorRequest("decision"))
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.OperatorApprove(ApproveCommand{
		DecisionCommand: DecisionCommand{ID: result.Grant.ID, Approver: "onur", ExpectedRevision: result.Grant.Revision},
		Duration:        time.Minute,
		MaxUses:         1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != StatusActive || approved.Revision != result.Grant.Revision+1 || approved.Duration != time.Minute {
		t.Fatalf("approved = %+v", approved)
	}
	current, err := store.OperatorRevoke(DecisionCommand{
		ID: approved.ID, Approver: "onur", ExpectedRevision: result.Grant.Revision,
	})
	var conflict *RevisionConflictError
	if !errors.As(err, &conflict) || current.Revision != approved.Revision || conflict.Current.Status != StatusActive {
		t.Fatalf("stale revoke = %+v err=%v", current, err)
	}

	second, _, err := store.Request(testOperatorRequest("bounds"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.OperatorApprove(ApproveCommand{
		DecisionCommand: DecisionCommand{ID: second.Grant.ID, Approver: "onur", ExpectedRevision: second.Grant.Revision},
		Duration:        second.Grant.Duration + time.Second,
	})
	if !errors.Is(err, ErrConstraintExceeded) {
		t.Fatalf("overbroad approval error = %v", err)
	}
}

func TestLifecycleEventsSurviveRestartAndWakeWaiters(t *testing.T) {
	path := t.TempDir() + "/grants.json"
	store := New(path, Options{})
	result, _, err := store.Request(testOperatorRequest("events"))
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.EventsAfter("", 100)
	if err != nil || len(page.Events) != 1 || page.Events[0].Kind != EventRequestCreated {
		t.Fatalf("created events = %+v err=%v", page, err)
	}
	approved, err := store.OperatorApprove(ApproveCommand{DecisionCommand: DecisionCommand{
		ID: result.Grant.ID, Approver: "onur", ExpectedRevision: result.Grant.Revision,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ReserveUse(approved.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordExecution(approved.ID, EventExecutionSucceeded); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(approved.ID); err != nil {
		t.Fatal(err)
	}

	restarted := New(path, Options{})
	recovered, err := restarted.EventsAfter(page.NextCursor, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := []EventKind{EventRequestApproved, EventGrantReserved, EventExecutionSucceeded, EventGrantConsumed}
	if len(recovered.Events) != len(want) {
		t.Fatalf("recovered events = %+v, want %v", recovered.Events, want)
	}
	for index, kind := range want {
		if recovered.Events[index].Kind != kind {
			t.Fatalf("event %d = %q, want %q", index, recovered.Events[index].Kind, kind)
		}
	}
}

func TestEventRetentionRejectsExpiredCursor(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{MaxEvents: 2})
	first, _, err := store.Request(testOperatorRequest("first"))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.EventsAfter("", 1)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := store.Request(testOperatorRequest("second"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OperatorDeny(DecisionCommand{ID: first.Grant.ID, Approver: "onur", ExpectedRevision: first.Grant.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.OperatorDeny(DecisionCommand{ID: second.Grant.ID, Approver: "onur", ExpectedRevision: second.Grant.Revision}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EventsAfter(initial.NextCursor, 10); !errors.Is(err, ErrCursorExpired) {
		t.Fatalf("compacted cursor error = %v", err)
	}
	if page, err := store.EventsAfter("", 10); err != nil || len(page.Events) != 2 {
		t.Fatalf("fresh compacted stream = %+v, %v", page, err)
	}
}

func TestQueryFiltersStatusGroupsAndValidation(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{})
	pending, _, err := store.Request(testOperatorRequest("pending"))
	if err != nil {
		t.Fatal(err)
	}
	activeResult, _, err := store.Request(testOperatorRequest("active"))
	if err != nil {
		t.Fatal(err)
	}
	active, err := store.OperatorApprove(ApproveCommand{DecisionCommand: DecisionCommand{
		ID: activeResult.Grant.ID, Approver: "onur", ExpectedRevision: activeResult.Grant.Revision,
	}})
	if err != nil {
		t.Fatal(err)
	}
	historyResult, _, err := store.Request(testOperatorRequest("history"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OperatorDeny(DecisionCommand{ID: historyResult.Grant.ID, Approver: "onur", ExpectedRevision: historyResult.Grant.Revision}); err != nil {
		t.Fatal(err)
	}
	queries := []struct {
		query grantsQueryAlias
		want  string
	}{
		{grantsQueryAlias{StatusGroup: StatusGroupPending}, pending.Grant.ID},
		{grantsQueryAlias{StatusGroup: StatusGroupActive}, active.ID},
		{grantsQueryAlias{StatusGroup: StatusGroupHistory}, historyResult.Grant.ID},
		{grantsQueryAlias{Client: "bob", Operation: "git.push.fast_forward", Target: &pending.Grant.Target}, pending.Grant.ID},
		{grantsQueryAlias{Target: &policy.Target{Kind: pending.Grant.Target.Kind}}, pending.Grant.ID},
	}
	for _, test := range queries {
		page, err := store.QueryGrants(Query(test.query))
		if err != nil || len(page.Grants) == 0 {
			t.Fatalf("QueryGrants(%+v) = %+v, %v", test.query, page, err)
		}
		found := false
		for _, grant := range page.Grants {
			found = found || grant.ID == test.want
		}
		if !found {
			t.Fatalf("QueryGrants(%+v) missing %s", test.query, test.want)
		}
	}
	invalid := []Query{
		{StatusGroup: "invalid"}, {Limit: -1}, {Limit: 101},
		{Target: &policy.Target{}},
		{Target: &policy.Target{Kind: "repo", Fields: map[string][]string{"": {"x"}}}},
		{Target: &policy.Target{Kind: "repo", Fields: map[string][]string{"name": {}}}},
		{Target: &policy.Target{Kind: "repo", Fields: map[string][]string{"name": {""}}}},
	}
	for _, query := range invalid {
		if _, err := store.QueryGrants(query); !errors.Is(err, ErrInvalidQuery) {
			t.Fatalf("QueryGrants(%+v) error = %v", query, err)
		}
	}
	if _, err := store.QueryGrants(Query{Cursor: strings.Repeat("x", 513)}); !errors.Is(err, ErrInvalidGrantCursor) {
		t.Fatalf("long cursor error = %v", err)
	}
}

func TestTargetFilterMatchesOnlySuppliedFields(t *testing.T) {
	target := policy.Target{Kind: "repository", Fields: map[string][]string{"owner": {"osolmaz"}, "name": {"demo"}}}
	if !targetMatchesFilter(target, policy.Target{Kind: "repository"}) {
		t.Fatal("kind-only filter did not match")
	}
	if !targetMatchesFilter(target, policy.Target{Kind: "repository", Fields: map[string][]string{"owner": {"osolmaz"}}}) {
		t.Fatal("partial field filter did not match")
	}
	if targetMatchesFilter(target, policy.Target{Kind: "repository", Fields: map[string][]string{"owner": {"other"}}}) ||
		targetMatchesFilter(target, policy.Target{Kind: "model"}) {
		t.Fatal("target filter accepted a mismatch")
	}
}

type grantsQueryAlias Query

func TestOperatorTerminalCommandsAndValidation(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{})
	result, _, err := store.Request(testOperatorRequest("terminal-deny"))
	if err != nil {
		t.Fatal(err)
	}
	denied, err := store.OperatorDeny(DecisionCommand{ID: result.Grant.ID, Approver: "onur", ExpectedRevision: result.Grant.Revision})
	if err != nil || denied.Revision != result.Grant.Revision+1 {
		t.Fatalf("terminal command = %+v, %v", denied, err)
	}
	activeResult, _, _ := store.Request(testOperatorRequest("revoke"))
	active, err := store.OperatorApprove(ApproveCommand{DecisionCommand: DecisionCommand{ID: activeResult.Grant.ID, Approver: "onur", ExpectedRevision: activeResult.Grant.Revision}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OperatorRevoke(DecisionCommand{ID: active.ID, Approver: "onur", ExpectedRevision: active.Revision}); err != nil {
		t.Fatal(err)
	}
	invalid := []DecisionCommand{
		{},
		{ID: pendingID(t, store, "bad-approver"), Approver: "bad\nname", ExpectedRevision: 1},
	}
	for _, command := range invalid {
		if _, err := store.OperatorDeny(command); !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("OperatorDeny(%+v) error = %v", command, err)
		}
	}
	if _, err := store.OperatorDeny(DecisionCommand{ID: "missing", Approver: "onur", ExpectedRevision: 1}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing decision error = %v", err)
	}
}

func TestEventValidationAndStatusKinds(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{})
	if _, err := store.EventsAfter("bad", 1); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("invalid event cursor error = %v", err)
	}
	for _, limit := range []int{-1, 101} {
		if _, err := store.EventsAfter("", limit); err == nil {
			t.Fatalf("EventsAfter(limit=%d) returned no error", limit)
		}
	}
	if _, err := store.RecordExecution("missing", EventRequestCreated); err == nil {
		t.Fatal("RecordExecution() accepted invalid kind")
	}
	if _, err := store.LatestEvent("missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("LatestEvent() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.WaitForEvents(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForEvents() error = %v", err)
	}
	for _, status := range []Status{StatusActive, StatusDenied, StatusCanceled, StatusExpired, StatusRevoked, StatusPending, StatusConsumed, "unknown"} {
		_ = statusEventKinds(Grant{Status: StatusPending}, Grant{Status: status})
	}
}

func TestOperatorDecisionReconcilesExpiryAndApprovalBounds(t *testing.T) {
	now := time.Date(2026, 7, 11, 1, 2, 3, 0, time.UTC)
	ids := []string{"grant-expire", "token-expire", "grant-bounds", "token-bounds"}
	store := newDeterministicStore(t, func() time.Time { return now }, &ids)
	expiring, _, err := store.Request(testOperatorRequest("expire"))
	if err != nil {
		t.Fatal(err)
	}
	now = expiring.Grant.PendingExpiresAt.Add(time.Second)
	current, err := store.OperatorDeny(DecisionCommand{ID: expiring.Grant.ID, Approver: "onur", ExpectedRevision: expiring.Grant.Revision})
	if !errors.Is(err, ErrRevisionConflict) || current.Status != StatusExpired || current.Revision != expiring.Grant.Revision+1 {
		t.Fatalf("expired decision = %+v, %v", current, err)
	}
	now = time.Date(2026, 7, 11, 2, 2, 3, 0, time.UTC)
	bounds, _, err := store.Request(testOperatorRequest("bounds-extra"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.OperatorDeny(DecisionCommand{ID: bounds.Grant.ID, Approver: "onur", ExpectedRevision: bounds.Grant.Revision + 1}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("status conflict error = %v", err)
	}
	for _, command := range []ApproveCommand{
		{DecisionCommand: DecisionCommand{ID: bounds.Grant.ID, Approver: "onur", ExpectedRevision: bounds.Grant.Revision}, Duration: -time.Second},
		{DecisionCommand: DecisionCommand{ID: bounds.Grant.ID, Approver: "onur", ExpectedRevision: bounds.Grant.Revision}, MaxUses: -1},
		{DecisionCommand: DecisionCommand{ID: bounds.Grant.ID, Approver: "onur", ExpectedRevision: bounds.Grant.Revision}, MaxUses: int(bounds.Grant.MaxUses + 1)},
	} {
		if _, err := store.OperatorApprove(command); !errors.Is(err, ErrConstraintExceeded) {
			t.Fatalf("OperatorApprove(%+v) error = %v", command, err)
		}
	}
}

func TestCursorDecodingAndEventPagingBranches(t *testing.T) {
	invalidJSON := base64.RawURLEncoding.EncodeToString([]byte(`{"created_at":"2026-07-11T01:02:03Z","id":"x","unknown":true}`))
	trailingJSON := base64.RawURLEncoding.EncodeToString([]byte(`{"created_at":"2026-07-11T01:02:03Z","id":"x"}{}`))
	emptyJSON := base64.RawURLEncoding.EncodeToString([]byte(`{}`))
	for _, cursor := range []string{"!!!", invalidJSON, trailingJSON, emptyJSON} {
		if _, err := decodeGrantCursor(cursor); !errors.Is(err, ErrInvalidGrantCursor) {
			t.Fatalf("decodeGrantCursor(%q) error = %v", cursor, err)
		}
	}
	store := New(t.TempDir()+"/grants.json", Options{})
	if page, err := store.EventsAfter("", 1); err != nil || len(page.Events) != 0 {
		t.Fatalf("empty EventsAfter() = %+v, %v", page, err)
	}
	for index := 0; index < 3; index++ {
		if _, _, err := store.Request(testOperatorRequest("page-" + string(rune('a'+index)))); err != nil {
			t.Fatal(err)
		}
	}
	page, err := store.EventsAfter("", 1)
	if err != nil || !page.HasMore || len(page.Events) != 1 {
		t.Fatalf("paged EventsAfter() = %+v, %v", page, err)
	}
	if latest, err := store.LatestEvent(page.Events[0].GrantID); err != nil || latest.Cursor == "" {
		t.Fatalf("LatestEvent() = %+v, %v", latest, err)
	}
}

func FuzzDecodeOperatorCursors(f *testing.F) {
	f.Add("")
	f.Add("!!!")
	f.Add(base64.RawURLEncoding.EncodeToString([]byte(`{"created_at":"2026-07-11T01:02:03Z","id":"request-1","query_hash":"hash"}`)))
	f.Fuzz(func(t *testing.T, cursor string) {
		grantCursor, grantErr := decodeGrantCursor(cursor)
		if grantErr == nil && cursor != "" {
			if _, err := decodeGrantCursor(encodeGrantCursor(grantCursor)); err != nil {
				t.Fatalf("grant cursor round trip: %v", err)
			}
		}
		sequence, eventErr := decodeEventCursor(cursor)
		if eventErr == nil {
			if decoded, err := decodeEventCursor(encodeEventCursor(sequence)); err != nil || decoded != sequence {
				t.Fatalf("event cursor round trip = %d, %v", decoded, err)
			}
		}
	})
}

func TestWaitForEventsEmitsTimeDrivenExpiry(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{PendingTimeout: 25 * time.Millisecond})
	result, _, err := store.Request(Request{
		Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"}, Reason: "expire without traffic",
	})
	if err != nil {
		t.Fatal(err)
	}
	created, err := store.EventsAfter("", 10)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	page, err := store.WaitForEvents(ctx, created.NextCursor)
	if err != nil || len(page.Events) != 1 || page.Events[0].Kind != EventRequestExpired {
		t.Fatalf("WaitForEvents() = %+v, %v", page, err)
	}
	grant, err := store.Get(result.Grant.ID)
	if err != nil || grant.Status != StatusExpired {
		t.Fatalf("expired grant = %+v, %v", grant, err)
	}
}

func TestWaitForDecisionReturnsApprovedGrant(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	requested := requestTestGrant(t, store, "wait-approved", 1)

	done := make(chan Grant, 1)
	errs := make(chan error, 1)
	go func() {
		grant, err := store.WaitForDecision(t.Context(), requested.Grant.ID)
		if err != nil {
			errs <- err
			return
		}
		done <- grant
	}()

	if _, err := store.Approve(requested.Grant.ID, requested.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errs:
		t.Fatalf("WaitForDecision() error = %v", err)
	case grant := <-done:
		if grant.Status != StatusActive {
			t.Fatalf("WaitForDecision() status = %q", grant.Status)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitForDecision() did not observe approval")
	}
}

func TestWaitForDecisionReturnsImmediateTerminalGrant(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	requested := requestTestGrant(t, store, "wait-denied", 1)
	if _, err := store.Deny(requested.Grant.ID, requested.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	grant, err := store.WaitForDecision(t.Context(), requested.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	if grant.Status != StatusDenied {
		t.Fatalf("WaitForDecision() status = %q", grant.Status)
	}
}

func TestWaitForDecisionHonorsCancellation(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "grants.json"), Options{})
	requested := requestTestGrant(t, store, "wait-canceled", 1)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := store.WaitForDecision(ctx, requested.Grant.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForDecision() error = %v", err)
	}
}

func TestDecisionLifecycleRecordContainsDurableAuditFields(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{})
	result, _, err := store.Request(testOperatorRequest("durable-audit"))
	if err != nil {
		t.Fatal(err)
	}
	approved, err := store.OperatorApprove(ApproveCommand{DecisionCommand: DecisionCommand{
		ID: result.Grant.ID, Approver: "onur", ExpectedRevision: result.Grant.Revision,
	}})
	if err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	data, err := store.load()
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	record := data.Events[len(data.Events)-1]
	if record.Approver != "onur" || record.PreviousStatus != StatusPending ||
		record.PreviousRevision != result.Grant.Revision || record.ExpectedRevision != result.Grant.Revision || record.Revision != approved.Revision {
		t.Fatalf("durable audit record = %+v", record)
	}
}

func TestLifecycleDeadlineVariantsAndSignalWake(t *testing.T) {
	now := time.Date(2026, 7, 11, 1, 2, 3, 0, time.UTC)
	store := New(t.TempDir()+"/grants.json", Options{Now: func() time.Time { return now }, ReservationTimeout: time.Minute})
	future := now.Add(5 * time.Minute)
	reservedAt := now.Add(-30 * time.Second)
	tests := []Grant{
		{Status: StatusPending, PendingExpiresAt: future},
		{Status: StatusActive, ExpiresAt: future},
		{Status: StatusActive, ExpiresAt: future, ReservedCount: 1, ReservedAt: reservedAt},
		{Status: StatusActive, ExpiresAt: future, ReservedCount: 1},
		{Status: StatusExpired, ReservedCount: 1, ReservedAt: reservedAt},
		{Status: StatusRevoked},
		{Status: StatusDenied}, {Status: StatusConsumed}, {Status: StatusCanceled}, {Status: "unknown"},
	}
	for _, grant := range tests {
		_ = store.grantLifecycleDeadline(grant, now)
	}
	for _, grant := range []Grant{
		{},
		{ReservedCount: 1, ReservationRetained: true},
		{Status: StatusActive, ReservedCount: 1, ReservedAt: now.Add(-2 * time.Minute)},
		{Status: StatusActive, ReservedCount: 1},
		{Status: StatusActive, ReservedCount: 1, ReservedAt: reservedAt},
	} {
		_ = store.reservationLifecycleDeadline(grant, now)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() {
		page, err := store.WaitForEvents(ctx, "")
		if err == nil && (len(page.Events) != 1 || page.Events[0].Kind != EventRequestCreated) {
			err = errors.New("unexpected event page")
		}
		result <- err
	}()
	time.Sleep(10 * time.Millisecond)
	if _, _, err := store.Request(testOperatorRequest("signal-wake")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func pendingID(t *testing.T, store *Store, id string) string {
	t.Helper()
	result, _, err := store.Request(testOperatorRequest(id))
	if err != nil {
		t.Fatal(err)
	}
	return result.Grant.ID
}

func testOperatorRequest(id string) Request {
	return Request{
		Client: "bob", ClientRequestID: id, Operation: "git.push.fast_forward",
		Target: repoTarget("demo"), Reason: "test operator inbox", Duration: 5 * time.Minute, MaxUses: 2,
	}
}
