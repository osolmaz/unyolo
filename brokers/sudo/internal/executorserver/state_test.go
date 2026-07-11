package executorserver

import (
	"errors"
	"path/filepath"
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
	record, claimed, err := state.claim("execution-1", "digest-1", "grant-1", "reservation-1")
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
	restarted, _ := newExecutionState(state.path, nil)
	replay, claimed, err := restarted.claim(record.ID, "digest-1", "grant-1", "reservation-1")
	if err != nil || claimed || replay.Status != executionComplete || replay.Outcome == nil || replay.Outcome.ExitCode != 7 {
		t.Fatalf("replay = %+v, %v, %v", replay, claimed, err)
	}
	if _, _, err := restarted.claim(record.ID, "other", "grant-1", "reservation-1"); !errors.Is(err, errExecutionConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, _, err := restarted.claim(record.ID, "digest-1", "grant-2", "reservation-1"); !errors.Is(err, errExecutionConflict) {
		t.Fatalf("cross-grant conflict error = %v", err)
	}
}

func TestExecutionStateLeavesInterruptedClaimsAmbiguous(t *testing.T) {
	t.Parallel()
	state, _ := newExecutionState(filepath.Join(t.TempDir(), "executions.json"), nil)
	_, _, _ = state.claim("execution-1", "digest-1", "grant-1", "reservation-1")
	record, claimed, err := state.claim("execution-1", "digest-1", "grant-1", "reservation-1")
	if err != nil || claimed || record.Status != executionClaimed {
		t.Fatalf("duplicate claim = %+v, %v, %v", record, claimed, err)
	}
	if err := state.markStarted("execution-1"); err != nil {
		t.Fatal(err)
	}
	record, claimed, err = state.claim("execution-1", "digest-1", "grant-1", "reservation-1")
	if err != nil || claimed || record.Status != executionStarted {
		t.Fatalf("duplicate started = %+v, %v, %v", record, claimed, err)
	}
}
