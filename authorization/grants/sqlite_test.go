package grants

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/authorization/activation"
	"github.com/osolmaz/unyolo/authorization/budget"
	"github.com/osolmaz/unyolo/authorization/policy"
	"github.com/osolmaz/unyolo/internal/storage/state"
	"github.com/osolmaz/unyolo/operation/digest"
)

func TestSQLiteStorePersistsLifecycleAndDecisionReplay(t *testing.T) {
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
	store := NewDatabase(database, Options{Now: func() time.Time { return now }, NewID: sequenceIDs("grant-id")})
	requested, created, err := store.Request(Request{Client: "bob", ClientRequestID: "request-1", Operation: "repo.create",
		Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"model/acme/demo"}}}, Reason: "test",
		Duration: 5 * time.Minute, MaxUses: 2})
	if err != nil || !created {
		t.Fatalf("Request() = %+v, %v, %v", requested, created, err)
	}
	pending, err := store.Get(requested.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	command := OperatorDecision{ID: pending.ID, Action: ActionApprove, Approver: "onur", ExpectedRevision: pending.Revision,
		IdempotencyKey: "approve-1"}
	decision, err := store.ApplyOperatorDecision(context.Background(), command, nil)
	if err != nil || decision.Grant.Status != StatusActive {
		t.Fatalf("ApplyOperatorDecision() = %+v, %v", decision, err)
	}
	if _, err := store.ReserveUse(pending.ID, "sqlite-use", pending.Operation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(pending.ID, "sqlite-use"); err != nil {
		t.Fatal(err)
	}

	restarted := NewDatabase(database, Options{Now: func() time.Time { return now }})
	stored, err := restarted.Get(pending.ID)
	if err != nil || stored.Status != StatusActive || stored.UsedCount != 1 {
		t.Fatalf("restarted Get() = %+v, %v", stored, err)
	}
	replay, err := restarted.ApplyOperatorDecision(context.Background(), command, nil)
	if err != nil || !replay.Replay || replay.Grant.Revision != decision.Grant.Revision {
		t.Fatalf("decision replay = %+v, %v", replay, err)
	}
	events, err := restarted.EventsAfter("", 100)
	if err != nil || len(events.Events) != 4 {
		t.Fatalf("EventsAfter() = %+v, %v", events, err)
	}
	var grantsCount, eventsCount, decisionsCount int
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM grants").Scan(&grantsCount); err != nil {
		t.Fatal(err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM lifecycle_events WHERE subject_kind = 'grant'").Scan(&eventsCount); err != nil {
		t.Fatal(err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM decision_records").Scan(&decisionsCount); err != nil {
		t.Fatal(err)
	}
	if grantsCount != 1 || eventsCount != 4 || decisionsCount != 1 {
		t.Fatalf("SQLite rows = grants %d events %d decisions %d", grantsCount, eventsCount, decisionsCount)
	}
}

func TestSQLiteStorePersistsAndReplaysTerminalActivationFailure(t *testing.T) {
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 8, 7, 4, 0, 0, 0, time.UTC)
	store := NewDatabase(database, Options{Now: func() time.Time { return now }, NewID: sequenceIDs("grant")})
	created, _, err := store.Request(Request{Client: "bob", Operation: "write", Target: policy.Target{Kind: "repo"},
		Reason: "update", Duration: time.Minute, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	command := OperatorDecision{ID: created.Grant.ID, Action: ActionApprove, Approver: "operator:onur",
		ExpectedRevision: created.Grant.Revision, IdempotencyKey: "failed-decision", CorrelationID: "correlation-1"}
	result, err := store.ApplyOperatorDecision(t.Context(), command, func(context.Context, Grant, ApprovalConstraints) error {
		return activation.New(activation.CodeCredentialChanged, errors.New("private credential detail"))
	})
	failure, ok := activation.As(err)
	if !ok || failure.Code != activation.CodeCredentialChanged || result.Grant.Status != StatusFailed {
		t.Fatalf("failed decision = %+v, %v", result, err)
	}

	restarted := NewDatabase(database, Options{Now: func() time.Time { return now }})
	stored, err := restarted.Get(created.Grant.ID)
	if err != nil || stored.Status != StatusFailed || stored.FailureCode != string(activation.CodeCredentialChanged) ||
		stored.FailureReference != "correlation-1" || stored.FailedAt.IsZero() {
		t.Fatalf("restarted Get() = %+v, %v", stored, err)
	}
	replay, err := restarted.ApplyOperatorDecision(t.Context(), command, func(context.Context, Grant, ApprovalConstraints) error {
		t.Fatal("validator called during failed replay")
		return nil
	})
	replayedFailure, ok := activation.As(err)
	if !ok || replayedFailure.Code != activation.CodeCredentialChanged || !replay.Replay || replay.Grant.Status != StatusFailed {
		t.Fatalf("failed replay = %+v, %v", replay, err)
	}
}

func TestSQLiteDecisionRoundTripPreservesImmutableJSON(t *testing.T) {
	record := state.GrantDecisionRecord{
		Scope: "grant-1\x00approve\x00key-1", RequestID: "grant-1", Action: "approve", IdempotencyKey: "key-1",
		CommandHash: strings.Repeat("a", 43), ResultJSON: []byte(`{"id":"grant-1"}`), PreviousJSON: []byte(`{}`),
		CommittedAt: time.Date(2026, 7, 20, 4, 0, 0, 0, time.UTC),
	}
	decoded, err := decisionFromSQLite(record)
	if err != nil {
		t.Fatalf("decisionFromSQLite() error = %v", err)
	}
	roundTrip, err := decisionToSQLite(decoded)
	if err != nil {
		t.Fatalf("decisionToSQLite() error = %v", err)
	}
	if string(roundTrip.ResultJSON) != string(record.ResultJSON) || string(roundTrip.PreviousJSON) != string(record.PreviousJSON) {
		t.Fatalf("decision JSON changed: result %q, previous %q", roundTrip.ResultJSON, roundTrip.PreviousJSON)
	}
}

func TestSQLiteStorePersistsUnlimitedUseBudget(t *testing.T) {
	t.Parallel()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := NewDatabase(database, Options{NewID: sequenceIDs("grant", "defaulted-grant")})
	result, created, err := store.Request(Request{
		Client: "bob", ClientRequestID: "unlimited", Operation: "write",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "continuous maintenance", Duration: time.Minute,
		MaxUses: usebudget.Unlimited, MaxUsesSpecified: true,
	})
	if err != nil || !created || !result.Grant.MaxUses.IsUnlimited() {
		t.Fatalf("Request() = %+v, %v, %v", result, created, err)
	}
	var maxUses, requestedMaxUses sql.NullInt64
	if err := database.SQL().QueryRowContext(t.Context(),
		"SELECT max_uses, requested_max_uses FROM grants WHERE id = ?", result.Grant.ID,
	).Scan(&maxUses, &requestedMaxUses); err != nil {
		t.Fatal(err)
	}
	if maxUses.Valid || requestedMaxUses.Valid {
		t.Fatalf("stored limits = %+v, %+v", maxUses, requestedMaxUses)
	}
	defaulted, created, err := store.Request(Request{
		Client: "bob", ClientRequestID: "defaulted", Operation: "write",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "default budget", Duration: time.Minute,
	})
	if err != nil || !created || !defaulted.Grant.RequestedMaxUsesDefaulted || defaulted.Grant.MaxUses != 1 {
		t.Fatalf("defaulted Request() = %+v, %v, %v", defaulted, created, err)
	}
	_, _, err = store.Request(Request{
		Client: "bob", ClientRequestID: "defaulted", Operation: "write",
		Target: policy.Target{Kind: "repo", Fields: map[string][]string{"name": {"demo"}}},
		Reason: "default budget", Duration: time.Minute, MaxUses: 1,
	})
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("explicit default replay error = %v", err)
	}
	restarted := NewDatabase(database, Options{})
	stored, err := restarted.Get(result.Grant.ID)
	if err != nil || !stored.MaxUses.IsUnlimited() || !stored.RequestedMaxUses.IsUnlimited() {
		t.Fatalf("Get() = %+v, %v", stored, err)
	}
	approved, err := restarted.ApplyOperatorDecision(t.Context(), OperatorDecision{
		ID: stored.ID, Action: ActionApprove, Approver: "onur",
		ExpectedRevision: stored.Revision, IdempotencyKey: "approve",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 3 {
		requestID := fmt.Sprintf("unlimited-use-%d", index)
		if _, err := restarted.ReserveUse(approved.Grant.ID, requestID, approved.Grant.Operation); err != nil {
			t.Fatal(err)
		}
		used, err := restarted.CommitUse(approved.Grant.ID, requestID)
		if err != nil || used.Grant.Status != StatusActive {
			t.Fatalf("CommitUse() = %+v, %v", used, err)
		}
	}
}

func TestSQLiteGrantRejectsInvalidPlanDigestMetadata(t *testing.T) {
	_, err := grantToSQLite(Grant{Metadata: map[string]string{"hf_plan_digest": "invalid"}})
	if err == nil {
		t.Fatal("grantToSQLite() accepted invalid plan digest metadata")
	}
}

func TestRequestWithPlanCommitsAndRollsBackAtomically(t *testing.T) {
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := NewDatabase(database, Options{NewID: sequenceIDs("grant-1", "grant-2")})
	createdAt := time.Date(2026, 7, 13, 3, 0, 0, 0, time.UTC)
	canonical := []byte(`{"schema":"provider/v1"}`)
	digest := plandigest.Digest(canonical)
	plan := ImmutablePlan{Digest: digest, SchemaName: "provider/v1", Canonical: canonical, CreatedAt: createdAt}
	request := Request{Client: "bob", ClientRequestID: "request-1", Operation: "repo.create",
		Target:   policy.Target{Kind: "test", Fields: map[string][]string{"name": {"repo"}}},
		Metadata: map[string]string{"test_plan_digest": digest}, Reason: "create", Duration: time.Minute, MaxUses: 1}
	result, created, err := store.RequestWithPlan(request, plan)
	if err != nil || !created || result.Grant.ID != "grant-1" {
		t.Fatalf("RequestWithPlan() = %+v, %v, %v", result, created, err)
	}
	if _, err := database.Plan(t.Context(), digest); err != nil {
		t.Fatalf("committed plan missing: %v", err)
	}

	failedCanonical := []byte(`{"schema":"provider/v2"}`)
	failedDigest := plandigest.Digest(failedCanonical)
	request.ClientRequestID = "request-2"
	request.Metadata["test_plan_digest"] = failedDigest
	request.Reason = strings.Repeat("x", 2_001)
	_, _, err = store.RequestWithPlan(request, ImmutablePlan{Digest: failedDigest, SchemaName: "provider/v2", Canonical: failedCanonical, CreatedAt: createdAt})
	if err == nil {
		t.Fatal("RequestWithPlan() accepted an oversized grant")
	}
	if _, err := database.Plan(t.Context(), failedDigest); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("rolled-back plan lookup error = %v", err)
	}
	var grantsCount int
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM grants").Scan(&grantsCount); err != nil || grantsCount != 1 {
		t.Fatalf("grant rows after rollback = %d, %v", grantsCount, err)
	}
}

func sequenceIDs(values ...string) func(int) (string, error) {
	index := 0
	return func(int) (string, error) {
		value := values[index]
		index++
		return value, nil
	}
}
