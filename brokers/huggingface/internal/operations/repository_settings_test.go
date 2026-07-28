package operations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/unyolo/brokers/huggingface/internal/hubclient"
)

func TestRepositorySettingsAdaptersExecuteAndReconcile(t *testing.T) {
	client := &settingsFake{repos: map[string]hubclient.RepoInfo{
		"model:acme/demo": {ID: "acme/demo", SHA: "abc", Private: false, Gated: hubclient.GatedDisabled},
	}}
	adapters, err := NewRepositorySettingsAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	target := json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo"}`)
	tests := []struct {
		name      string
		arguments json.RawMessage
		prepare   func()
	}{
		{name: "repo.visibility.update", arguments: json.RawMessage(`{"visibility":"private"}`), prepare: func() { client.reset() }},
		{name: "repo.gating.update", arguments: json.RawMessage(`{"mode":"manual"}`), prepare: func() { client.reset() }},
		{name: "repo.move", arguments: json.RawMessage(`{"owner":"acme","name":"renamed"}`), prepare: func() { client.reset() }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.prepare()
			adapter, _ := registry.Lookup(test.name)
			input, err := adapter.Decode(target, test.arguments)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(context.Background(), input)
			if err != nil || plan.Policy.Operation == "" || plan.Presentation.Title == "" {
				t.Fatalf("Resolve() = %+v, %v", plan, err)
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

func TestRepositorySettingsAdapterRejectsStaleAndUnknownInputs(t *testing.T) {
	client := &settingsFake{repos: map[string]hubclient.RepoInfo{"model:acme/demo": {ID: "acme/demo", SHA: "abc"}}}
	adapters, _ := NewRepositorySettingsAdapters(client)
	adapter := adapters[2]
	target := json.RawMessage(`{"kind":"repo","type":"model","owner":"acme","name":"demo"}`)
	if _, err := adapter.Decode(target, json.RawMessage(`{"visibility":"private","token":"bad"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	input, _ := adapter.Decode(target, json.RawMessage(`{"visibility":"private"}`))
	plan, _ := adapter.Resolve(context.Background(), input)
	client.repos["model:acme/demo"] = hubclient.RepoInfo{ID: "acme/demo", SHA: "changed"}
	if _, err := adapter.Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("stale plan error = %v", err)
	}
}

type settingsFake struct {
	repos map[string]hubclient.RepoInfo
}

func (f *settingsFake) reset() {
	f.repos = map[string]hubclient.RepoInfo{"model:acme/demo": {ID: "acme/demo", SHA: "abc", Gated: hubclient.GatedDisabled}}
}

func repoKey(ref hubclient.RepoRef) string { return string(ref.Type) + ":" + ref.ID() }

func (f *settingsFake) RepoInfo(_ context.Context, ref hubclient.RepoRef) (hubclient.RepoInfo, error) {
	value, found := f.repos[repoKey(ref)]
	if !found {
		return hubclient.RepoInfo{}, &hubclient.Error{Code: hubclient.CodeNotFound}
	}
	return value, nil
}

func (f *settingsFake) MoveRepo(_ context.Context, from hubclient.RepoRef, owner, name string) error {
	value, found := f.repos[repoKey(from)]
	if !found {
		return errors.New("source missing")
	}
	delete(f.repos, repoKey(from))
	value.ID = owner + "/" + name
	f.repos[string(from.Type)+":"+value.ID] = value
	return nil
}

func (f *settingsFake) UpdateRepoVisibility(_ context.Context, ref hubclient.RepoRef, visibility hubclient.Visibility) (hubclient.RepoSettings, error) {
	value := f.repos[repoKey(ref)]
	value.Private = visibility == hubclient.VisibilityPrivate
	f.repos[repoKey(ref)] = value
	return hubclient.RepoSettings{Visibility: visibility}, nil
}

func (f *settingsFake) UpdateRepoGating(_ context.Context, ref hubclient.RepoRef, mode hubclient.GatedMode) error {
	value := f.repos[repoKey(ref)]
	value.Gated = mode
	f.repos[repoKey(ref)] = value
	return nil
}
