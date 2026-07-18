package operations

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
)

type repositoryReadFake struct{}

func (repositoryReadFake) RepoInfo(context.Context, hubclient.RepoRef) (hubclient.RepoInfo, error) {
	return hubclient.RepoInfo{ID: "alice/private", SHA: "abc", Private: true, SDK: "docker"}, nil
}

func (repositoryReadFake) ListRepos(context.Context, hubclient.RepoType, string, int) ([]hubclient.RepoSummary, error) {
	return []hubclient.RepoSummary{{ID: "alice/private", SHA: "abc", Private: true}, {ID: "alice/denied", Private: true}}, nil
}

func (repositoryReadFake) RepoTree(context.Context, hubclient.RepoRef, string, string, bool) ([]hubclient.RepoTreeEntry, error) {
	return []hubclient.RepoTreeEntry{{Type: "file", Path: "README.md", OID: "abc", Size: 4}}, nil
}

func (repositoryReadFake) RepoFile(context.Context, hubclient.RepoRef, string, string) (hubclient.RepoFile, error) {
	return hubclient.RepoFile{Content: []byte("read me"), ContentType: "text/plain", Commit: "abc"}, nil
}

func TestRepositoryReadAdaptersExecuteEveryBoundOperation(t *testing.T) {
	adapters, err := NewRepositoryReadAdapters(repositoryReadFake{}, func(_ string, target hfpolicy.Target) bool {
		return target.Name == "private"
	})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]struct{ target, arguments string }{
		"repo.metadata.read": {`{"kind":"repo","type":"dataset","owner":"alice","name":"private"}`, `{}`},
		"repo.list":          {`{"kind":"repo","type":"dataset","owner":"alice","name":"*"}`, `{"limit":10}`},
		"repo.tree.list":     {`{"kind":"repo","type":"dataset","owner":"alice","name":"private"}`, `{"path":"docs","recursive":true}`},
		"repo.contents.read": {`{"kind":"repo","type":"dataset","owner":"alice","name":"private"}`, `{"path":"README.md"}`},
	}
	for _, adapter := range adapters {
		name := adapter.Descriptor().Name
		fixture := inputs[name]
		input, decodeErr := adapter.Decode(json.RawMessage(fixture.target), json.RawMessage(fixture.arguments))
		if decodeErr != nil {
			t.Fatalf("%s decode: %v", name, decodeErr)
		}
		plan, resolveErr := adapter.Resolve(t.Context(), input)
		if resolveErr != nil {
			t.Fatalf("%s resolve: %v", name, resolveErr)
		}
		plan.Policy.Client = "agent"
		if adapter.Authorize(plan).Operation == "" || adapter.Present(plan).Title == "" {
			t.Fatalf("%s omitted authorization or presentation", name)
		}
		outcome, executeErr := adapter.Execute(t.Context(), plan)
		if executeErr != nil || !outcome.Proven || len(outcome.Result) == 0 {
			t.Fatalf("%s execute = %#v, %v", name, outcome, executeErr)
		}
		if name == "repo.list" && (strings.Contains(string(outcome.Result), "denied") || strings.Contains(string(outcome.Result), `"private":`)) {
			t.Fatalf("repo.list leaked filtered metadata: %s", outcome.Result)
		}
		if name == "repo.contents.read" && !strings.Contains(string(outcome.Result), `"encoding":"utf-8"`) {
			t.Fatalf("content result = %s", outcome.Result)
		}
		if reconciled, reconcileErr := adapter.Reconcile(t.Context(), plan); reconcileErr != nil || !reconciled.Proven {
			t.Fatalf("%s reconcile = %#v, %v", name, reconciled, reconcileErr)
		}
	}
}

func TestRepositoryReadAdaptersRejectInvalidConfigurationAndInput(t *testing.T) {
	if _, err := NewRepositoryReadAdapters(nil, func(string, hfpolicy.Target) bool { return true }); err == nil {
		t.Fatal("nil repository client accepted")
	}
	if _, err := NewRepositoryReadAdapters(repositoryReadFake{}, nil); err == nil {
		t.Fatal("nil disclosure accepted")
	}
	adapters, err := NewRepositoryReadAdapters(repositoryReadFake{}, func(string, hfpolicy.Target) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	for _, adapter := range adapters {
		if _, err := adapter.Decode(json.RawMessage(`{}`), json.RawMessage(`{}`)); err == nil {
			t.Fatalf("%s accepted invalid target", adapter.Descriptor().Name)
		}
	}
}
