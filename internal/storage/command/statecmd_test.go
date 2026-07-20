package statecmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/internal/storage/state"
)

func TestStateCommandsCheckBackupExportAndRestore(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "state")
	database, err := state.Open(t.Context(), directory, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := database.PutPlan(t.Context(), "test.io/plan/v1", []byte(`{"secret":"hidden"}`), testTime())
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	var output, stderr bytes.Buffer
	if err := Run(t.Context(), []string{"check", "--state-dir", directory, "--full"}, &output, &stderr); err != nil ||
		!strings.Contains(output.String(), `"full_check":"ok"`) {
		t.Fatalf("check output=%s stderr=%s err=%v", output.String(), stderr.String(), err)
	}
	backup := filepath.Join(root, "backup")
	output.Reset()
	if err := Run(t.Context(), []string{"backup", "--state-dir", directory, "--output", backup}, &output, &stderr); err != nil ||
		!strings.Contains(output.String(), `"format":"brokerkit.io/state-backup/v1"`) {
		t.Fatalf("backup output=%s stderr=%s err=%v", output.String(), stderr.String(), err)
	}
	export := filepath.Join(root, "export.json")
	output.Reset()
	if err := Run(t.Context(), []string{"export", "--state-dir", directory, "--output", export}, &output, &stderr); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(root, "replacement")
	replacementDB, err := state.Open(t.Context(), replacement, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := replacementDB.Close(); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if err := Run(t.Context(), []string{"restore", "--state-dir", replacement, "--backup", backup}, &output, &stderr); err != nil {
		t.Fatal(err)
	}
	restored, err := state.OpenExisting(t.Context(), replacement, state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = restored.Close() }()
	if _, err := restored.Plan(t.Context(), digest); err != nil {
		t.Fatalf("restored plan is missing: %v", err)
	}
}

func TestStateCommandsRejectIncompleteAndRelativeArguments(t *testing.T) {
	for _, args := range [][]string{{}, {"unknown"}, {"check"}, {"backup", "--state-dir", "relative", "--output", "/tmp/out"},
		{"restore", "--state-dir", "/tmp/state"}, {"export", "--state-dir", "/tmp/state", "--output", "relative"}} {
		if err := Run(t.Context(), args, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid arguments accepted: %v", args)
		}
	}
}

func testTime() time.Time {
	return time.Date(2026, time.July, 15, 0, 0, 0, 0, time.UTC)
}
