package transaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRunRollsBackCompletedStepsInReverse(t *testing.T) {
	coordinator := Coordinator{StateDirectory: filepath.Join(t.TempDir(), "state")}
	var calls []string
	steps := []Step{
		{ID: "one", Kind: "component:one", Apply: func(context.Context) (string, error) { calls = append(calls, "apply-one"); return "one-handle", nil }, Rollback: func(_ context.Context, handle string) error { calls = append(calls, "rollback-"+handle); return nil }},
		{ID: "two", Kind: "component:two", Apply: func(context.Context) (string, error) {
			calls = append(calls, "apply-two")
			return "", errors.New("boom")
		}, Rollback: func(context.Context, string) error { return nil }},
	}
	if err := coordinator.Run(context.Background(), "deployment", "plan", "candidate", "previous", steps); err == nil {
		t.Fatal("Run() succeeded")
	}
	want := []string{"apply-one", "apply-two", "rollback-one-handle"}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("calls = %v, want %v", calls, want)
	}
	if _, found, err := coordinator.read(); err != nil || found {
		t.Fatalf("journal remains: found=%v err=%v", found, err)
	}
}

func TestRunCommitsAndRejectsInvalidSteps(t *testing.T) {
	coordinator := Coordinator{StateDirectory: filepath.Join(t.TempDir(), "state")}
	applied := false
	steps := []Step{{ID: "one", Kind: "component:one", Apply: func(context.Context) (string, error) { applied = true; return "handle", nil }, Rollback: func(context.Context, string) error { return nil }}}
	if err := coordinator.Run(context.Background(), "deployment", "plan", "candidate", "previous", steps); err != nil || !applied {
		t.Fatalf("Run() = applied %v, %v", applied, err)
	}
	if _, found, err := coordinator.read(); err != nil || found {
		t.Fatalf("journal remains: %v, %v", found, err)
	}
	for _, invalid := range [][]Step{
		nil,
		{{ID: "", Kind: "component", Apply: func(context.Context) (string, error) { return "", nil }}},
		{{ID: "same", Kind: "one", Apply: func(context.Context) (string, error) { return "", nil }}, {ID: "same", Kind: "two", Apply: func(context.Context) (string, error) { return "", nil }}},
	} {
		if err := coordinator.Run(context.Background(), "deployment", "plan", "candidate", "previous", invalid); err == nil {
			t.Fatalf("invalid steps were accepted: %#v", invalid)
		}
	}
}

func TestRecoverUsesDurableHandles(t *testing.T) {
	coordinator := Coordinator{StateDirectory: filepath.Join(t.TempDir(), "state")}
	if err := ensureTestDirectory(coordinator.StateDirectory); err != nil {
		t.Fatal(err)
	}
	journal := Journal{APIVersion: APIVersion, ID: "id", DeploymentDigest: "deployment", PlanDigest: "plan", CandidateBundle: "candidate", Phase: "applying", Steps: []StepRecord{{ID: "one", Kind: "component:one", State: "complete", RollbackHandle: "opaque"}}}
	if err := coordinator.write(journal); err != nil {
		t.Fatal(err)
	}
	called := ""
	if err := coordinator.Recover(context.Background(), map[string]func(context.Context, string) error{"component:one": func(_ context.Context, handle string) error { called = handle; return nil }}); err != nil {
		t.Fatal(err)
	}
	if called != "opaque" {
		t.Fatalf("rollback handle = %q", called)
	}
	if err := coordinator.Recover(context.Background(), nil); err != nil {
		t.Fatalf("empty recovery = %v", err)
	}

	if err := ensureTestDirectory(coordinator.StateDirectory); err != nil {
		t.Fatal(err)
	}
	journal.Steps[0].Kind = "missing"
	if err := coordinator.write(journal); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Recover(context.Background(), nil); err == nil {
		t.Fatal("missing recovery handler was accepted")
	}
}

func TestRecoverPreservesUncertainRunningStep(t *testing.T) {
	coordinator := Coordinator{StateDirectory: filepath.Join(t.TempDir(), "state")}
	if err := ensureTestDirectory(coordinator.StateDirectory); err != nil {
		t.Fatal(err)
	}
	journal := Journal{
		APIVersion: APIVersion, ID: "id", DeploymentDigest: "deployment", PlanDigest: "plan",
		CandidateBundle: "candidate", Phase: "applying",
		Steps: []StepRecord{{ID: "one", Kind: "component:one", State: "running"}},
	}
	if err := coordinator.write(journal); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Recover(context.Background(), nil); err == nil {
		t.Fatal("uncertain running step was cleared")
	}
	current, found, err := coordinator.read()
	if err != nil || !found || current.Phase != "recovery_required" || current.Steps[0].State != "running" {
		t.Fatalf("journal = %#v, found=%v, err=%v", current, found, err)
	}
}

func ensureTestDirectory(path string) error { return os.MkdirAll(path, 0o700) }
