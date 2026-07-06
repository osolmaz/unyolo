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
			{"id": "osolmaz/data", "type": "dataset", "mode": "read-only",
			 "grant_policy": {
			   "git_receive_pack": {"max_uses": 3},
			   "repo_metadata_update": {},
			   "repo_visibility_update": {"allowed": ["public_to_private"]}
			 }}
		],
		"buckets": [
			{"id": "osolmaz/bucket", "mode": "append-only", "snapshot_prefix": "snapshots/",
			 "grant_policy": {"bucket_delete": {"allowed": ["object", "prefix"]}}}
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
	repo, ok := scp.Repo(TypeDataset, "osolmaz", "data")
	if !ok {
		t.Fatalf("missing dataset repo")
	}
	if repo.GrantPolicy.GitReceivePack == nil || repo.GrantPolicy.GitReceivePack.DefaultMinutes != DefaultGrantMinutes || repo.GrantPolicy.GitReceivePack.MaxUses != 3 {
		t.Fatalf("repo git grant policy = %+v", repo.GrantPolicy.GitReceivePack)
	}
	if repo.GrantPolicy.RepoMetadataUpdate == nil || repo.GrantPolicy.RepoMetadataUpdate.MaxMinutes != MaxGrantMinutes {
		t.Fatalf("repo metadata grant policy = %+v", repo.GrantPolicy.RepoMetadataUpdate)
	}
	if repo.GrantPolicy.RepoVisibilityUpdate == nil || strings.Join(repo.GrantPolicy.RepoVisibilityUpdate.Allowed, ",") != "public_to_private" {
		t.Fatalf("repo visibility grant policy = %+v", repo.GrantPolicy.RepoVisibilityUpdate)
	}
	if got := scp.DecideRepo(TypeDataset, "osolmaz", "missing", OpGitFetch); got.Allowed || got.Reason != "repository is not in scope" {
		t.Fatalf("missing decision = %+v", got)
	}
	if got := scp.Buckets(); len(got) != 1 || got[0].SnapshotPrefix != "snapshots/" {
		t.Fatalf("Buckets() = %+v", got)
	} else if got[0].GrantPolicy.BucketDelete == nil || strings.Join(got[0].GrantPolicy.BucketDelete.Allowed, ",") != "object,prefix" {
		t.Fatalf("bucket grant policy = %+v", got[0].GrantPolicy.BucketDelete)
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

func TestScopeExampleParses(t *testing.T) {
	if _, err := LoadFile(filepath.Join("..", "..", "scope.example.json")); err != nil {
		t.Fatalf("scope.example.json is invalid: %v", err)
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
		{name: "unknown repo grant field", body: `{"repos": [{"id": "a/b", "type": "model", "grant_policy": {"bad": {}}}]}`, want: "unknown field"},
		{name: "empty repo grant policy", body: `{"repos": [{"id": "a/b", "type": "model", "grant_policy": {}}]}`, want: "at least one action"},
		{name: "zero repo grant minutes", body: `{"repos": [{"id": "a/b", "type": "model", "grant_policy": {"git_receive_pack": {"default_minutes": 0}}}]}`, want: "default_minutes"},
		{name: "bad repo grant use cap", body: `{"repos": [{"id": "a/b", "type": "model", "grant_policy": {"git_receive_pack": {"default_max_uses": 4, "max_uses": 3}}}]}`, want: "max_uses"},
		{name: "zero repo grant uses", body: `{"repos": [{"id": "a/b", "type": "model", "grant_policy": {"git_receive_pack": {"max_uses": 0}}}]}`, want: "max_uses"},
		{name: "bad visibility grant direction", body: `{"repos": [{"id": "a/b", "type": "model", "grant_policy": {"repo_visibility_update": {"allowed": ["public"]}}}]}`, want: "unsupported value"},
		{name: "empty bucket grant policy", body: `{"buckets": [{"id": "a/b", "grant_policy": {}}]}`, want: "at least one action"},
		{name: "zero bucket grant minutes", body: `{"buckets": [{"id": "a/b", "grant_policy": {"bucket_delete": {"max_minutes": 0, "allowed": ["object"]}}}]}`, want: "max_minutes"},
		{name: "missing bucket delete shape", body: `{"buckets": [{"id": "a/b", "grant_policy": {"bucket_delete": {}}}]}`, want: "at least one value"},
		{name: "bad bucket delete shape", body: `{"buckets": [{"id": "a/b", "grant_policy": {"bucket_delete": {"allowed": ["bucket"]}}}]}`, want: "unsupported value"},
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
