package grants

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/policy"
	"github.com/osolmaz/brokerkit/state"
)

func TestSQLiteStorePersistsLifecycleAndDecisionReplay(t *testing.T) {
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 2, 0, 0, 0, time.UTC)
	store := NewDatabase(database, Options{Now: func() time.Time { return now }, NewID: sequenceIDs("grant-id", "decision-token", "notification-token")})
	requested, created, err := store.Request(Request{Client: "bob", ClientRequestID: "request-1", Operation: "repo.create",
		Target: policy.Target{Kind: "hf", Fields: map[string][]string{"name": {"model/acme/demo"}}}, Reason: "test",
		Duration: 5 * time.Minute, MaxUses: 2})
	if err != nil || !created {
		t.Fatalf("Request() = %+v, %v, %v", requested, created, err)
	}
	claim, claimed, err := store.ClaimNotification(requested.Grant.ID, time.Minute)
	if err != nil || !claimed || claim.DecisionToken != "notification-token" {
		t.Fatalf("ClaimNotification() = %+v, %v, %v", claim, claimed, err)
	}
	ref := MessageRef{Kind: "telegram", ChatID: 1, MessageID: 2, Text: "approve"}
	if _, recorded, err := store.SetNotificationIfClaimed(claim.Grant.ID, claim.Grant.NotificationClaimedAt, ref); err != nil || !recorded {
		t.Fatalf("SetNotificationIfClaimed() = %v, %v", recorded, err)
	}
	pending, err := store.Get(requested.Grant.ID)
	if err != nil {
		t.Fatal(err)
	}
	command := OperatorDecision{ID: pending.ID, Action: ActionApprove, Approver: "onur", ExpectedRevision: pending.Revision,
		IdempotencyKey: "approve-1", Reason: "approved"}
	decision, err := store.ApplyOperatorDecision(context.Background(), command, nil)
	if err != nil || decision.Grant.Status != StatusActive {
		t.Fatalf("ApplyOperatorDecision() = %+v, %v", decision, err)
	}
	if _, err := store.ReserveUse(pending.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CommitUse(pending.ID); err != nil {
		t.Fatal(err)
	}

	restarted := NewDatabase(database, Options{Now: func() time.Time { return now }})
	stored, err := restarted.Get(pending.ID)
	if err != nil || stored.Status != StatusActive || stored.UsedCount != 1 || stored.Notification == nil || *stored.Notification != ref {
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
	var grantsCount, eventsCount, decisionsCount, outboxCount, outboxAttempts int
	var outboxStatus string
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM grants").Scan(&grantsCount); err != nil {
		t.Fatal(err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM lifecycle_events WHERE subject_kind = 'grant'").Scan(&eventsCount); err != nil {
		t.Fatal(err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM decision_records").Scan(&decisionsCount); err != nil {
		t.Fatal(err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*), status, attempts FROM notification_outbox GROUP BY status, attempts").Scan(&outboxCount, &outboxStatus, &outboxAttempts); err != nil {
		t.Fatal(err)
	}
	if grantsCount != 1 || eventsCount != 4 || decisionsCount != 1 || outboxCount != 1 || outboxStatus != "delivered" || outboxAttempts != 1 {
		t.Fatalf("SQLite rows = grants %d events %d decisions %d outbox %d/%s/%d", grantsCount, eventsCount, decisionsCount, outboxCount, outboxStatus, outboxAttempts)
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
	store := NewDatabase(database, Options{NewID: sequenceIDs("grant-1", "token-1", "grant-2", "token-2")})
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
	var grantsCount, outboxCount int
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM grants").Scan(&grantsCount); err != nil || grantsCount != 1 {
		t.Fatalf("grant rows after rollback = %d, %v", grantsCount, err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT count(*) FROM notification_outbox").Scan(&outboxCount); err != nil || outboxCount != 1 {
		t.Fatalf("outbox rows after rollback = %d, %v", outboxCount, err)
	}
}

func TestSQLiteNotificationOutboxRecoversAmbiguousClaim(t *testing.T) {
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	now := time.Date(2026, 7, 13, 4, 0, 0, 0, time.UTC)
	store := NewDatabase(database, Options{Now: func() time.Time { return now }, NewID: sequenceIDs("grant", "token", "claim-1", "claim-2")})
	requested, _, err := store.Request(Request{Client: "bob", ClientRequestID: "request", Operation: "repo.create",
		Target: policy.Target{Kind: "test", Fields: map[string][]string{"name": {"repo"}}}, Reason: "test", Duration: time.Minute, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	claim, claimed, err := store.ClaimNotification(requested.Grant.ID, time.Minute)
	if err != nil || !claimed {
		t.Fatalf("first claim = %+v, %v, %v", claim, claimed, err)
	}
	if _, retained, err := store.RetainNotificationClaim(claim.Grant.ID, claim.Grant.NotificationClaimedAt); err != nil || !retained {
		t.Fatalf("retain = %v, %v", retained, err)
	}
	var status string
	var attempts int
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT status, attempts FROM notification_outbox").Scan(&status, &attempts); err != nil || status != "ambiguous" || attempts != 1 {
		t.Fatalf("ambiguous outbox = %s/%d, %v", status, attempts, err)
	}
	if due, err := store.ApprovalNotificationsDue(); err != nil || len(due) != 0 {
		t.Fatalf("pre-lease ApprovalNotificationsDue() = %+v, %v", due, err)
	}
	now = now.Add(time.Minute + time.Second)
	if due, err := store.ApprovalNotificationsDue(); err != nil || len(due) != 1 || due[0].ID != requested.Grant.ID {
		t.Fatalf("post-lease ApprovalNotificationsDue() = %+v, %v", due, err)
	}
	if _, claimed, err := store.ClaimNotification(requested.Grant.ID, time.Minute); err != nil || !claimed {
		t.Fatalf("reclaim = %v, %v", claimed, err)
	}
	if err := database.SQL().QueryRowContext(t.Context(), "SELECT status, attempts FROM notification_outbox").Scan(&status, &attempts); err != nil || status != "claimed" || attempts != 2 {
		t.Fatalf("reclaimed outbox = %s/%d, %v", status, attempts, err)
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
