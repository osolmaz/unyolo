package operations

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
)

type contentFake struct {
	identity   string
	info       hubclient.RepoInfo
	pathInfo   hubclient.RepoPathInfo
	read       []byte
	commits    []hubclient.CommitRequest
	duplicates int
}

func (f *contentFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *contentFake) RepoInfoRevision(context.Context, hubclient.RepoRef, string) (hubclient.RepoInfo, error) {
	return f.info, nil
}

func (f *contentFake) RepoPathsInfo(context.Context, hubclient.RepoRef, string, []string) ([]hubclient.RepoPathInfo, error) {
	return []hubclient.RepoPathInfo{f.pathInfo}, nil
}

func (f *contentFake) ReadRepoFile(context.Context, hubclient.RepoRef, string, string) ([]byte, error) {
	return f.read, nil
}

func (f *contentFake) DuplicateLFSFile(context.Context, hubclient.RepoRef, hubclient.RepoRef, hubclient.RepoPathInfo) error {
	f.duplicates++
	return nil
}

func (f *contentFake) CreateCommit(_ context.Context, request hubclient.CommitRequest) (hubclient.CommitResult, error) {
	f.commits = append(f.commits, request)
	return hubclient.CommitResult{CommitURL: "https://huggingface.co/commit/abcdef1", CommitOID: "abcdef1"}, nil
}

func TestRepositoryContentAdaptersExecuteAllVariants(t *testing.T) {
	hash := strings.Repeat("a", 64)
	tests := []struct {
		name      string
		repoType  string
		arguments json.RawMessage
		paths     []string
	}{
		{"repo.commit.create", "model", json.RawMessage(`{"summary":"commit","operations":[{"kind":"file","path":"file.txt","content_base64":"ZGF0YQ=="},{"kind":"deleted_file","path":"old.txt"}]}`), []string{"file.txt", "old.txt"}},
		{"repo.file.upload", "model", json.RawMessage(`{"path":"file.txt","content_base64":"ZGF0YQ==","summary":"upload"}`), []string{"file.txt"}},
		{"repo.file.delete", "model", json.RawMessage(`{"path":"dir/","folder":true,"summary":"delete"}`), []string{"dir/"}},
		{"repo.file.copy", "model", json.RawMessage(`{"source_type":"dataset","source_owner":"source","source_name":"data","source_revision":"main","source_path":"src.txt","path":"copied.txt","summary":"copy"}`), []string{"copied.txt"}},
		{"space.hot_reload.apply", "space", json.RawMessage(`{"summary":"reload","operations":[{"kind":"lfs_file","path":"large.bin","oid":"` + hash + `","size":12}]}`), []string{"large.bin"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &contentFake{identity: "operator", info: hubclient.RepoInfo{ID: "acme/demo", SHA: "abc"},
				pathInfo: hubclient.RepoPathInfo{Type: "file", Path: "src.txt", OID: "blob", Size: 4}, read: []byte("data")}
			adapters, err := NewRepositoryContentAdapters(client)
			if err != nil {
				t.Fatal(err)
			}
			registry, _ := NewRegistry(adapters...)
			adapter, _ := registry.Lookup(test.name)
			kind := "repo"
			if test.name == "space.hot_reload.apply" {
				kind = "space"
			}
			target := json.RawMessage(`{"kind":"` + kind + `","type":"` + test.repoType + `","owner":"acme","name":"demo","revision":"main"}`)
			input, err := adapter.Decode(target, test.arguments)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			assertPlanReconstruction(t, adapter, plan)
			if plan.Policy.Target.Refs[0] != "main" || !slices.Equal(plan.Policy.Target.Paths, test.paths) {
				t.Fatalf("policy target = %#v", plan.Policy.Target)
			}
			if test.name == "repo.file.copy" && (plan.Policy.Attrs["source"] != "dataset/source/data" ||
				plan.Policy.Attrs["source_ref"] != "main" || plan.Policy.Attrs["source_path"] != "src.txt") {
				t.Fatalf("copy policy attrs = %#v", plan.Policy.Attrs)
			}
			outcome, err := adapter.Execute(context.Background(), plan)
			if err != nil || !outcome.Proven || len(client.commits) != 1 {
				t.Fatalf("Execute() = %#v, %v; commits=%d", outcome, err, len(client.commits))
			}
			if test.name == "space.hot_reload.apply" && !client.commits[0].HotReload {
				t.Fatal("hot reload query was not bound")
			}
		})
	}
}

func TestRepositoryContentCopyBindsSourceAndTargetState(t *testing.T) {
	client := &contentFake{identity: "operator", info: hubclient.RepoInfo{ID: "acme/demo", SHA: "abc"},
		pathInfo: hubclient.RepoPathInfo{Type: "file", Path: "src.bin", OID: "blob", Size: 4, LFSSHA: strings.Repeat("a", 64), XetHash: strings.Repeat("b", 64)}}
	adapters, _ := NewRepositoryContentAdapters(client)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("repo.file.copy")
	target := json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo","revision":"main"}`)
	arguments := json.RawMessage(`{"source_type":"dataset","source_owner":"source","source_name":"data","source_revision":"main","source_path":"src.bin","path":"copy.bin","summary":"copy"}`)
	input, _ := adapter.Decode(target, arguments)
	plan, _ := adapter.Resolve(context.Background(), input)
	client.pathInfo.OID = "changed"
	if _, err := adapter.Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("source drift error = %v", err)
	}
	client.pathInfo.OID = "blob"
	client.identity = "different"
	if _, err := adapter.Execute(context.Background(), plan); err == nil {
		t.Fatal("credential drift accepted")
	}
}
