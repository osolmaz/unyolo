package coverage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestParseTotal(t *testing.T) {
	total, err := parseTotal([]byte("example.go:1:\tFunc\t80.0%\ntotal:\t(statements)\t87.5%\n"))
	if err != nil || total != 87.5 {
		t.Fatalf("parseTotal() = %v, %v", total, err)
	}
}

func TestRunRejectsInvalidMinimum(t *testing.T) {
	if _, err := Run(context.Background(), t.TempDir(), 101); err == nil {
		t.Fatal("Run() unexpectedly accepted invalid minimum")
	}
}

func TestRunExecutesCoverageGate(t *testing.T) {
	directory := t.TempDir()
	writeTestFile(t, directory, "go.mod", "module example.test/coverage\n\ngo 1.25.0\n")
	writeTestFile(t, directory, "value.go", "package value\nfunc Value() int { return 1 }\n")
	writeTestFile(t, directory, "value_test.go", "package value\nimport \"testing\"\nfunc TestValue(t *testing.T) { if Value() != 1 { t.Fail() } }\n")
	if total, err := Run(t.Context(), directory, 100); err != nil || total != 100 {
		t.Fatalf("Run() = %v, %v", total, err)
	}
	if _, err := Run(t.Context(), directory, 101); err == nil {
		t.Fatal("Run() accepted impossible threshold")
	}
}

func TestRunReportsTestAndCoverageFailures(t *testing.T) {
	failing := t.TempDir()
	writeTestFile(t, failing, "go.mod", "module example.test/failing\n\ngo 1.25.0\n")
	writeTestFile(t, failing, "value.go", "package value\nfunc Value() int { return 1 }\n")
	writeTestFile(t, failing, "value_test.go", "package value\nimport \"testing\"\nfunc TestValue(t *testing.T) { t.Fail() }\n")
	if _, err := Run(t.Context(), failing, 0); err == nil {
		t.Fatal("Run() accepted failing tests")
	}

	low := t.TempDir()
	writeTestFile(t, low, "go.mod", "module example.test/low\n\ngo 1.25.0\n")
	writeTestFile(t, low, "value.go", "package value\nfunc Covered() int { return 1 }\nfunc Uncovered() int { return 2 }\n")
	writeTestFile(t, low, "value_test.go", "package value\nimport \"testing\"\nfunc TestCovered(t *testing.T) { if Covered() != 1 { t.Fail() } }\n")
	if _, err := Run(t.Context(), low, 100); err == nil {
		t.Fatal("Run() accepted coverage below the threshold")
	}
}

func writeTestFile(t *testing.T, directory, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
