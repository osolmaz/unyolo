package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseAndDecideRepo(t *testing.T) {
	scp, err := Parse([]byte(`{
		"repos": [
			{"id": "osolmaz/model", "type": "model"},
			{"id": "osolmaz/data", "type": "dataset", "mode": "read-only"}
		],
		"buckets": [
			{"id": "osolmaz/bucket", "mode": "append-only", "snapshot_prefix": "snapshots/"}
		]
	}`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := scp.DecideRepo(TypeModel, "osolmaz", "model", OpGitPush); !got.Allowed {
		t.Fatalf("model push decision = %+v", got)
	}
	if got := scp.DecideRepo(TypeDataset, "osolmaz", "data", OpGitPush); got.Allowed || got.Reason != "repository is read-only" {
		t.Fatalf("dataset push decision = %+v", got)
	}
	if got := scp.DecideRepo(TypeDataset, "osolmaz", "data", OpGitFetch); !got.Allowed {
		t.Fatalf("dataset fetch decision = %+v", got)
	}
	if got := scp.DecideRepo(TypeDataset, "osolmaz", "missing", OpGitFetch); got.Allowed || got.Reason != "repository is not in scope" {
		t.Fatalf("missing decision = %+v", got)
	}
	if got := scp.Buckets(); len(got) != 1 || got[0].SnapshotPrefix != "snapshots/" {
		t.Fatalf("Buckets() = %+v", got)
	}
	if got := scp.DecideRepo(TypeModel, "osolmaz", "model", Operation("unknown")); got.Allowed || got.Reason != "operation is not supported" {
		t.Fatalf("unknown op decision = %+v", got)
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope.json")
	if err := os.WriteFile(path, []byte(`{"repos":[{"id":"a/b","type":"model"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	scp, err := LoadFile(path)
	if err != nil {
		t.Fatalf("LoadFile() error = %v", err)
	}
	if _, ok := scp.Repo(TypeModel, "a", "b"); !ok {
		t.Fatalf("LoadFile() missing repo")
	}
}

func TestParseRejectsInvalidScope(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "unknown field", body: `{"repos": [], "extra": true}`, want: "unknown field"},
		{name: "trailing content", body: `{"repos": []} {"repos": []}`, want: "trailing content"},
		{name: "bad id", body: `{"repos": [{"id": "a/b/c", "type": "model"}]}`, want: "owner/name"},
		{name: "bad type", body: `{"repos": [{"id": "a/b", "type": "bucket"}]}`, want: "type must"},
		{name: "bad mode", body: `{"repos": [{"id": "a/b", "type": "model", "mode": "write"}]}`, want: "mode must"},
		{name: "bad snapshot prefix", body: `{"buckets": [{"id": "a/b", "snapshot_prefix": "../snapshots/"}]}`, want: "snapshot_prefix"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Parse() error = %v, want containing %q", err, tc.want)
			}
		})
	}
}
