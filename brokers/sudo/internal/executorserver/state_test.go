package executorserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/executorprotocol"
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
