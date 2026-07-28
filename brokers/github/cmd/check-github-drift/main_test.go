package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/unyolo/brokers/github/internal/upstreamdrift"
)

func TestRunWithWritesCleanReportAndStatus(t *testing.T) {
	root := commandTestRoot(t)
	reportPath := filepath.Join(t.TempDir(), "nested", "report.md")
	statusPath := filepath.Join(t.TempDir(), "status.txt")
	snapshot := commandSnapshot("repos/list", false)

	var stdout bytes.Buffer
	err := runWith(checkRuntime{
		args:    []string{"-output", reportPath, "-status-output", statusPath},
		stdout:  &stdout,
		timeout: time.Minute,
		root:    func() (string, error) { return root, nil },
		loadPinned: func(path string) (upstreamdrift.SnapshotSet, error) {
			if !strings.HasSuffix(path, filepath.Join("brokers", "github", "internal", "upstream", "snapshots")) {
				t.Fatalf("unexpected snapshot path %q", path)
			}
			return snapshot, nil
		},
		fetchCurrent: func(ctx context.Context, query []byte) (upstreamdrift.SnapshotSet, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("fetch context has no deadline")
			}
			if string(query) != "query { viewer { login } }\n" {
				t.Fatalf("unexpected query %q", query)
			}
			return snapshot, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	assertFileContains(t, reportPath, "No structural drift detected")
	assertFileContains(t, statusPath, "clean\n")
}

func TestRunWithWritesDriftToStdout(t *testing.T) {
	root := commandTestRoot(t)
	statusPath := filepath.Join(t.TempDir(), "status.txt")

	var stdout bytes.Buffer
	err := runWith(checkRuntime{
		args:       []string{"-status-output", statusPath},
		stdout:     &stdout,
		timeout:    time.Minute,
		root:       func() (string, error) { return root, nil },
		loadPinned: func(string) (upstreamdrift.SnapshotSet, error) { return commandSnapshot("repos/list", false), nil },
		fetchCurrent: func(context.Context, []byte) (upstreamdrift.SnapshotSet, error) {
			return commandSnapshot("repos/view", true), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if output := stdout.String(); !strings.Contains(output, "Structural drift detected") || !strings.Contains(output, "`operation` changed `GET /repos`") {
		t.Fatalf("stdout report = %q", output)
	}
	assertFileContains(t, statusPath, "drift\n")
}

func TestParseOptionsRejectsUnknownFlags(t *testing.T) {
	if _, err := parseOptions([]string{"-unknown"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func TestRepositoryRootWalksParents(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "brokers", "github", "cmd")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
	if err := os.Chdir(nested); err != nil {
		t.Fatal(err)
	}
	found, err := repositoryRoot()
	if err != nil || found != root {
		t.Fatalf("repositoryRoot() = %q, %v", found, err)
	}
}

func commandTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	queryPath := filepath.Join(root, "brokers", "github", "internal", "upstream", "graphql-introspection.graphql")
	if err := os.MkdirAll(filepath.Dir(queryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(queryPath, []byte("query { viewer { login } }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func commandSnapshot(operationID string, deprecated bool) upstreamdrift.SnapshotSet {
	retrieved := time.Date(2026, 7, 15, 1, 2, 3, 0, time.UTC)
	return upstreamdrift.SnapshotSet{
		REST:        []byte(`{"paths":{"/repos":{"get":{"operationId":"` + operationID + `","deprecated":` + commandBool(deprecated) + `,"responses":{"200":{}}}}}}`),
		GraphQL:     []byte(`{"data":{"__schema":{"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"viewer","args":[],"type":{"kind":"SCALAR","name":"String"},"isDeprecated":false,"deprecationReason":null}]},{"kind":"SCALAR","name":"String","fields":null}]}}}`),
		Permissions: []byte(`{"contents":{"permissions":[{"verb":"GET","requestPath":"/repos","access":"read","server-to-server":true}]}}`),
		APIVersions: []string{"2022-11-28"},
		Sources:     []upstreamdrift.Source{{Kind: "rest", RetrievedAt: retrieved}},
	}
}

func commandBool(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want && !strings.Contains(string(data), want) {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}
