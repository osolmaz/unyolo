package operations

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
)

func TestRefsAdaptersExecuteAndReconcile(t *testing.T) {
	client := &refsFake{}
	adapters, err := NewRefsAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	tests := []struct {
		name      string
		ref       string
		arguments json.RawMessage
		prepare   func()
	}{
		{name: "repo.branch.create", ref: "release", arguments: json.RawMessage(`{"starting_point":"main"}`), prepare: func() {
			client.refs = hubclient.Refs{Branches: []hubclient.GitRef{{Name: "main", TargetCommit: "abcdef1"}}}
		}},
		{name: "repo.branch.delete", ref: "release", arguments: json.RawMessage(`{}`), prepare: func() {
			client.refs = hubclient.Refs{Branches: []hubclient.GitRef{{Name: "release", TargetCommit: "abcdef1"}}}
		}},
		{name: "repo.tag.create", ref: "v1.0", arguments: json.RawMessage(`{"revision":"main","message":"release"}`), prepare: func() {
			client.refs = hubclient.Refs{Branches: []hubclient.GitRef{{Name: "main", TargetCommit: "abcdef1"}}}
		}},
		{name: "repo.tag.delete", ref: "v1.0", arguments: json.RawMessage(`{}`), prepare: func() {
			client.refs = hubclient.Refs{Tags: []hubclient.GitRef{{Name: "v1.0", TargetCommit: "abcdef1"}}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare()
			adapter, _ := registry.Lookup(test.name)
			target := json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo","ref":"` + test.ref + `"}`)
			input, err := adapter.Decode(target, test.arguments)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			assertPlanReconstruction(t, adapter, plan)
			if _, err := adapter.Execute(context.Background(), plan); err != nil {
				t.Fatal(err)
			}
			outcome, err := adapter.Reconcile(context.Background(), plan)
			if err != nil || !outcome.Proven {
				t.Fatalf("Reconcile() = %+v, %v", outcome, err)
			}
		})
	}
}

func TestRefsAdaptersRejectUnknownAndExistingCreate(t *testing.T) {
	client := &refsFake{refs: hubclient.Refs{Branches: []hubclient.GitRef{{Name: "main", TargetCommit: "abc"}}}}
	adapters, _ := NewRefsAdapters(client)
	adapter := adapters[0]
	target := json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo","ref":"main"}`)
	if _, err := adapter.Decode(target, json.RawMessage(`{"starting_point":"main","unknown":true}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	input, _ := adapter.Decode(target, json.RawMessage(`{"starting_point":"main"}`))
	if _, err := adapter.Resolve(context.Background(), input); err == nil {
		t.Fatal("existing branch creation resolved")
	}
}

func TestRefsCreateReconciliationRequiresExactApprovedCommit(t *testing.T) {
	client := &refsFake{refs: hubclient.Refs{Branches: []hubclient.GitRef{{Name: "main", TargetCommit: "abcdef1"}}}}
	adapters, _ := NewRefsAdapters(client)
	adapter := adapters[0]
	input, _ := adapter.Decode(json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo","ref":"release"}`), json.RawMessage(`{"starting_point":"main"}`))
	plan, err := adapter.Resolve(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	client.refs.Branches = append(client.refs.Branches, hubclient.GitRef{Name: "release", TargetCommit: "deadbee"})
	outcome, err := adapter.Reconcile(t.Context(), plan)
	if err != nil || outcome.Proven {
		t.Fatalf("wrong-commit reconciliation = %+v, %v", outcome, err)
	}
}

type refsFake struct{ refs hubclient.Refs }

func (f *refsFake) ListRefs(context.Context, hubclient.RepoRef) (hubclient.Refs, error) {
	return f.refs, nil
}

func (f *refsFake) CreateBranch(_ context.Context, _ hubclient.RepoRef, branch, commit string) error {
	f.refs.Branches = append(f.refs.Branches, hubclient.GitRef{Name: branch, TargetCommit: commit})
	return nil
}

func (f *refsFake) DeleteBranch(_ context.Context, _ hubclient.RepoRef, branch string) error {
	for index, value := range f.refs.Branches {
		if value.Name == branch {
			f.refs.Branches = append(f.refs.Branches[:index], f.refs.Branches[index+1:]...)
			return nil
		}
	}
	return errors.New("branch missing")
}

func (f *refsFake) CreateTag(_ context.Context, _ hubclient.RepoRef, tag, _, commit string) error {
	f.refs.Tags = append(f.refs.Tags, hubclient.GitRef{Name: tag, TargetCommit: commit})
	return nil
}

func (f *refsFake) DeleteTag(_ context.Context, _ hubclient.RepoRef, tag string) error {
	for index, value := range f.refs.Tags {
		if value.Name == tag {
			f.refs.Tags = append(f.refs.Tags[:index], f.refs.Tags[index+1:]...)
			return nil
		}
	}
	return errors.New("tag missing")
}
