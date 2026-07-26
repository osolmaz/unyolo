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
}

func ensureTestDirectory(path string) error { return os.MkdirAll(path, 0o700) }
