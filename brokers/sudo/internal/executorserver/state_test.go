package executorserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/sudo/internal/executorprotocol"
)

func TestExecutionStateClaimsPersistsAndReplays(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	state, err := newExecutionState(filepath.Join(t.TempDir(), "executions.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	record, claimed, err := state.claim("execution-1", digest, "grant-1", "reservation-1")
	if err != nil || !claimed || record.Status != executionClaimed {
		t.Fatalf("claim = %+v, %v, %v", record, claimed, err)
	}
	if err := state.markStarted(record.ID); err != nil {
		t.Fatal(err)
	}
	outcome := executorprotocol.Outcome{Started: true, ExitCode: 7}
	if err := state.complete(record.ID, outcome); err != nil {
		t.Fatal(err)
	}
	restarted, _ := newExecutionState(state.path, func() time.Time { return now })
	replay, claimed, err := restarted.claim(record.ID, digest, "grant-1", "reservation-1")
	if err != nil || claimed || replay.Status != executionComplete || replay.Outcome == nil || replay.Outcome.ExitCode != 7 {
		t.Fatalf("replay = %+v, %v, %v", replay, claimed, err)
	}
	if _, _, err := restarted.claim(record.ID, "other", "grant-1", "reservation-1"); !errors.Is(err, errExecutionConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, _, err := restarted.claim(record.ID, digest, "grant-2", "reservation-1"); !errors.Is(err, errExecutionConflict) {
		t.Fatalf("cross-grant conflict error = %v", err)
	}
}

func TestExecutionStateRejectsMalformedDurableData(t *testing.T) {
	t.Parallel()
	for name, data := range map[string]string{
		"unknown field": `{"version":1,"executions":[],"unknown":true}`,
		"duplicate key": `{"version":1,"version":1,"executions":[]}`,
		"old schema":    `{"version":0,"executions":[]}`,
		"trailing data": `{"version":1,"executions":[]} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "executions.json")
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			state, _ := newExecutionState(path, nil)
			if _, _, err := state.lookup("id", strings.Repeat("a", 64), "grant", "reservation"); err == nil {
				t.Fatal("malformed state was accepted")
			}
		})
	}
}

func TestExecutionStatePrunesOnlyOldCompletedRecords(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0).UTC()
	state, _ := newExecutionState(filepath.Join(t.TempDir(), "executions.json"), func() time.Time { return now })
	digest := strings.Repeat("a", 64)
	for _, id := range []string{"old-complete", "uncertain"} {
		_, _, _ = state.claim(id, digest, "grant-"+id, "reservation-"+id)
		_ = state.markStarted(id)
	}
	_ = state.complete("old-complete", executorprotocol.Outcome{Started: true})
	data, err := state.load()
	if err != nil {
		t.Fatal(err)
	}
	old := now.Add(-completedRetention - time.Hour)
	data.Executions[0].ClaimedAt = old.Add(-2 * time.Second)
	data.Executions[0].StartedAt = old.Add(-time.Second)
	data.Executions[0].CompletedAt = old
	if err := state.save(data); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state.claim("new", digest, "grant-new", "reservation-new"); err != nil {
		t.Fatal(err)
	}
	loaded, err := state.load()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, record := range loaded.Executions {
		ids[record.ID] = true
	}
	if ids["old-complete"] || !ids["uncertain"] || !ids["new"] {
		t.Fatalf("retained execution ids = %v", ids)
	}
}

func TestExecutionStateLeavesInterruptedClaimsAmbiguous(t *testing.T) {
	t.Parallel()
	state, _ := newExecutionState(filepath.Join(t.TempDir(), "executions.json"), nil)
	digest := strings.Repeat("a", 64)
	_, _, _ = state.claim("execution-1", digest, "grant-1", "reservation-1")
	record, claimed, err := state.claim("execution-1", digest, "grant-1", "reservation-1")
	if err != nil || claimed || record.Status != executionClaimed {
		t.Fatalf("duplicate claim = %+v, %v, %v", record, claimed, err)
	}
	if err := state.markStarted("execution-1"); err != nil {
		t.Fatal(err)
	}
	record, claimed, err = state.claim("execution-1", digest, "grant-1", "reservation-1")
	if err != nil || claimed || record.Status != executionStarted {
		t.Fatalf("duplicate started = %+v, %v, %v", record, claimed, err)
	}
}

func TestExecutionRecordValidationRejectsInconsistentStates(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	base := executionRecord{ID: "execution", PlanDigest: strings.Repeat("a", 64), GrantID: "grant", ReservationID: "reservation", ClaimedAt: now}
	valid := base
	valid.Status, valid.StartedAt, valid.CompletedAt = executionComplete, now.Add(time.Second), now.Add(2*time.Second)
	valid.Outcome = &executorprotocol.Outcome{Started: true}
	if err := validateExecutionRecord(valid); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*executionRecord){
		func(record *executionRecord) { record.ID = "" },
		func(record *executionRecord) { record.Status = "unknown" },
		func(record *executionRecord) { record.Status = executionClaimed; record.StartedAt = now },
		func(record *executionRecord) { record.Status = executionStarted; record.StartedAt = time.Time{} },
		func(record *executionRecord) { record.Outcome = nil },
		func(record *executionRecord) { record.CompletedAt = record.ClaimedAt.Add(-time.Second) },
	} {
		changed := valid
		mutate(&changed)
		if err := validateExecutionRecord(changed); err == nil {
			t.Fatalf("invalid record was accepted: %+v", changed)
		}
	}
}

func TestExecutionStateRejectsInvalidOperationsAndCapacity(t *testing.T) {
	t.Parallel()
	if _, err := newExecutionState("", nil); err == nil {
		t.Fatal("empty state path was accepted")
	}
	state, _ := newExecutionState(filepath.Join(t.TempDir(), "state.json"), nil)
	if err := state.markStarted("missing"); err == nil {
		t.Fatal("missing execution was started")
	}
	digest := strings.Repeat("a", 64)
	_, _, _ = state.claim("execution", digest, "grant", "reservation")
	if err := state.complete("execution", executorprotocol.Outcome{}); err == nil {
		t.Fatal("claimed execution completed before start")
	}
	if err := state.markStarted("execution"); err != nil {
		t.Fatal(err)
	}
	if err := state.complete("execution", executorprotocol.Outcome{}); err != nil {
		t.Fatal(err)
	}
	if err := state.complete("execution", executorprotocol.Outcome{}); err == nil {
		t.Fatal("completed execution was completed twice")
	}
	tooMany := executionFile{Version: 1, Executions: make([]executionRecord, maxStateRecords+1)}
	if err := state.save(tooMany); err == nil {
		t.Fatal("oversized execution state was saved")
	}
	emptyPath := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(emptyPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	empty, _ := newExecutionState(emptyPath, nil)
	if _, _, err := empty.lookup("id", digest, "grant", "reservation"); err == nil {
		t.Fatal("empty durable state was accepted")
	}
}
