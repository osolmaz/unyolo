package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/upstreamdrift"
)

func TestRunWithWritesDriftOutputs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, pinnedSnapshot)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	pinned := `{"paths":{"/api/models":{"get":{"operationId":"listModels","responses":{"200":{}}}}}}`
	if err := os.WriteFile(path, []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(root, "output", "report.md")
	statusPath := filepath.Join(root, "output", "status")
	var stdout strings.Builder
	err := runWith(runtime{
		args:    []string{"-output", reportPath, "-status-output", statusPath},
		stdout:  &stdout,
		timeout: time.Second,
		root:    func() (string, error) { return root, nil },
		fetch: func(context.Context) ([]byte, upstreamdrift.Source, error) {
			return []byte(`{"paths":{"/api/models":{"get":{"operationId":"listModels","deprecated":true,"responses":{"200":{}}}}}}`), upstreamdrift.Source{URL: upstreamdrift.SourceURL, RetrievedAt: time.Now()}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	report, err := os.ReadFile(reportPath)
	if err != nil || !strings.Contains(string(report), "Structural drift detected") {
		t.Fatalf("report = %q, %v", report, err)
	}
	status, err := os.ReadFile(statusPath)
	if err != nil || string(status) != "drift\n" {
		t.Fatalf("status = %q, %v", status, err)
	}
}

func TestRunWithReportsCleanToStdout(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, pinnedSnapshot)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	document := []byte(`{"paths":{"/api/models":{"get":{"operationId":"listModels","responses":{"200":{}}}}}}`)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout strings.Builder
	err := runWith(runtime{
		stdout:  &stdout,
		timeout: time.Second,
		root:    func() (string, error) { return root, nil },
		fetch: func(context.Context) ([]byte, upstreamdrift.Source, error) {
			return document, upstreamdrift.Source{URL: upstreamdrift.SourceURL, RetrievedAt: time.Now()}, nil
		},
	})
	if err != nil || !strings.Contains(stdout.String(), "No structural drift detected") {
		t.Fatalf("runWith() = %q, %v", stdout.String(), err)
	}
}

func TestParseOptionsRejectsInvalidFlag(t *testing.T) {
	if _, err := parseOptions([]string{"-missing"}); err == nil {
		t.Fatal("invalid flag accepted")
	}
}

func TestFindRepositoryRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	got, err := findRepositoryRoot(nested)
	if err != nil || got != root {
		t.Fatalf("findRepositoryRoot() = %q, %v", got, err)
	}
	if _, err := findRepositoryRoot(t.TempDir()); err == nil {
		t.Fatal("missing repository root accepted")
	}
}
