package policypreset

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteOutputsCreatesAndReplacesCompleteSet(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "profile.json"), filepath.Join(dir, "scope.json"), filepath.Join(dir, "manifest.json")}
	outputs := testOutputs(paths, "first")
	if err := WriteOutputs(outputs, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		assertOutput(t, path, "first")
	}
	var existing *ExistingOutputError
	if err := WriteOutputs(testOutputs(paths, "second"), false); !errors.As(err, &existing) {
		t.Fatalf("create existing error = %v", err)
	}
	for _, path := range paths {
		assertOutput(t, path, "first")
	}
	if err := WriteOutputs(testOutputs(paths, "second"), true); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		assertOutput(t, path, "second")
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".*.stage")); err != nil || len(matches) != 0 {
		t.Fatalf("staging files = %v, error = %v", matches, err)
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".*.backup")); err != nil || len(matches) != 0 {
		t.Fatalf("backup files = %v, error = %v", matches, err)
	}
}

func TestWriteOutputsRollsBackPartialCreate(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.json")
	second := filepath.Join(dir, "second.json")
	if err := os.WriteFile(second, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteOutputs(testOutputs([]string{first, second}, "candidate"), false)
	if err == nil {
		t.Fatal("partial create succeeded")
	}
	if _, err := os.Stat(first); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first output survived rollback: %v", err)
	}
	data, readErr := os.ReadFile(second) // #nosec G304 -- test reads its own temp output.
	if readErr != nil || string(data) != "existing" {
		t.Fatalf("existing output = %q, error = %v", data, readErr)
	}
}

func TestWriteOutputsRejectsUnsafeOrOverlappingOutputs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	for _, outputs := range [][]Output{
		{},
		{{Path: path, Data: []byte("x")}, {Path: path, Data: []byte("y")}},
		{{Path: path, Data: []byte("x"), Mode: 0o666}},
	} {
		if err := WriteOutputs(outputs, false); err == nil {
			t.Fatalf("WriteOutputs(%+v) succeeded", outputs)
		}
	}
}

func TestBackupKeepsOriginalPathPresent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.json")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, err := stageOutput(Output{Path: path, Data: []byte("replacement"), Mode: 0o640})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cleanupStaged([]*stagedOutput{staged}) })
	if err := backupOutput(staged); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- test reads its own temp output.
	if err != nil || string(data) != "existing" {
		t.Fatalf("original after backup = %q, error = %v", data, err)
	}
}

func testOutputs(paths []string, body string) []Output {
	result := make([]Output, 0, len(paths))
	for _, path := range paths {
		result = append(result, Output{Path: path, Data: []byte(body), Mode: 0o640})
	}
	return result
}

func assertOutput(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test reads its own temp output.
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("%s mode = %04o", path, info.Mode().Perm())
	}
}
