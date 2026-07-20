package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadWriteJSONAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "value.json")
	var missing struct{ Name string }
	if err := ReadJSON(path, &missing); err != nil {
		t.Fatalf("ReadJSON(missing) error = %v", err)
	}
	if err := WriteJSONAtomic(path, map[string]string{"name": "brokerkit"}, 0o600); err != nil {
		t.Fatalf("WriteJSONAtomic() error = %v", err)
	}
	var got struct{ Name string }
	if err := ReadJSON(path, &got); err != nil {
		t.Fatalf("ReadJSON() error = %v", err)
	}
	if got.Name != "brokerkit" {
		t.Fatalf("decoded name = %q, want brokerkit", got.Name)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestReadJSONMissingAndEmptyResetOutput(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	got := struct{ Name string }{Name: "stale"}
	if err := ReadJSON(missing, &got); err != nil {
		t.Fatalf("ReadJSON(missing) error = %v", err)
	}
	if got.Name != "" {
		t.Fatalf("ReadJSON(missing) left stale value %q, want zero", got.Name)
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	got.Name = "stale"
	if err := ReadJSON(empty, &got); err != nil {
		t.Fatalf("ReadJSON(empty) error = %v", err)
	}
	if got.Name != "" {
		t.Fatalf("ReadJSON(empty) left stale value %q, want zero", got.Name)
	}
}

func TestReadJSONResetsStructBeforeDecode(t *testing.T) {
	dir := t.TempDir()
	emptyObject := filepath.Join(dir, "empty-object.json")
	if err := os.WriteFile(emptyObject, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := struct{ Name string }{Name: "stale"}
	if err := ReadJSON(emptyObject, &got); err != nil {
		t.Fatalf("ReadJSON(empty object) error = %v", err)
	}
	if got.Name != "" {
		t.Fatalf("ReadJSON(empty object) left stale value %q, want zero", got.Name)
	}

	nullObject := filepath.Join(dir, "null.json")
	if err := os.WriteFile(nullObject, []byte("null"), 0o600); err != nil {
		t.Fatal(err)
	}
	got.Name = "stale"
	if err := ReadJSON(nullObject, &got); err != nil {
		t.Fatalf("ReadJSON(null) error = %v", err)
	}
	if got.Name != "" {
		t.Fatalf("ReadJSON(null) left stale value %q, want zero", got.Name)
	}
}

func TestReadJSONResetsMapBeforeDecode(t *testing.T) {
	dir := t.TempDir()
	partialMap := filepath.Join(dir, "partial-map.json")
	if err := os.WriteFile(partialMap, []byte(`{"new":"value"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"old": "stale"}
	if err := ReadJSON(partialMap, &values); err != nil {
		t.Fatalf("ReadJSON(partial map) error = %v", err)
	}
	if _, ok := values["old"]; ok {
		t.Fatalf("ReadJSON(partial map) kept stale key: %+v", values)
	}
	if values["new"] != "value" {
		t.Fatalf("ReadJSON(partial map) = %+v, want new value", values)
	}
}

func TestWriteFileAtomicAndReadErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "raw.txt")
	if err := WriteFileAtomic(path, []byte("raw"), 0o600); err != nil {
		t.Fatalf("WriteFileAtomic() error = %v", err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is created inside t.TempDir by this test.
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "raw" {
		t.Fatalf("raw data = %q, want raw", string(data))
	}

	badJSON := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badJSON, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out map[string]string
	if err := ReadJSON(badJSON, &out); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("ReadJSON(bad) error = %v, want decode error", err)
	}
}

func TestWriteJSONAtomicEncodeError(t *testing.T) {
	err := WriteJSONAtomic(filepath.Join(t.TempDir(), "bad.json"), map[string]any{"bad": make(chan int)}, 0o600)
	if err == nil || !strings.Contains(err.Error(), "encode") {
		t.Fatalf("WriteJSONAtomic(bad) error = %v, want encode error", err)
	}
}

func TestWriteFileAtomicDirectoryErrors(t *testing.T) {
	dir := t.TempDir()
	parentFile := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(parentFile, []byte("file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(filepath.Join(parentFile, "child"), []byte("x"), 0o600); err == nil {
		t.Fatal("WriteFileAtomic(parent file) error = nil, want error")
	}
	if err := WriteFileAtomic(dir, []byte("x"), 0o600); err == nil {
		t.Fatal("WriteFileAtomic(replace dir) error = nil, want error")
	}
}
