package operations

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
)

func TestSpaceAdaptersExecuteAndReconcile(t *testing.T) {
	client := &spaceFake{}
	adapters, err := NewSpaceAdapters(client)
	if err != nil {
		t.Fatal(err)
	}
	registry, _ := NewRegistry(adapters...)
	target := json.RawMessage(`{"kind":"space","owner":"acme","name":"demo"}`)
	tests := []struct {
		name      string
		arguments json.RawMessage
		prepare   func()
	}{
		{name: "space.restart", arguments: json.RawMessage(`{"factory_reboot":false}`), prepare: func() { client.reset() }},
		{name: "space.pause", arguments: json.RawMessage(`{}`), prepare: func() { client.reset() }},
		{name: "space.hardware.update", arguments: json.RawMessage(`{"flavor":"t4-small"}`), prepare: func() { client.reset() }},
		{name: "space.sleep_time.update", arguments: json.RawMessage(`{"seconds":3600}`), prepare: func() { client.reset() }},
		{name: "space.dev_mode.enable", arguments: json.RawMessage(`{}`), prepare: func() { client.reset() }},
		{name: "space.dev_mode.disable", arguments: json.RawMessage(`{}`), prepare: func() { client.reset(); client.runtime.DevMode = true }},
		{name: "space.variable.set", arguments: json.RawMessage(`{"key":"MODE","value":"production","description":"mode"}`), prepare: func() { client.reset() }},
		{name: "space.variable.delete", arguments: json.RawMessage(`{"key":"MODE"}`), prepare: func() { client.reset(); client.variables["MODE"] = hubclient.SpaceVariable{Value: "old"} }},
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
			if err != nil || plan.Presentation.Title == "" {
				t.Fatalf("Resolve() = %+v, %v", plan, err)
			}
			if test.name == "space.variable.set" && strings.Contains(plan.Presentation.Summary, "production") {
				t.Fatal("variable value leaked into presentation")
			}
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

func TestSpaceAdapterRejectsUnknownAndStaleInput(t *testing.T) {
	client := &spaceFake{}
	client.reset()
	adapters, _ := NewSpaceAdapters(client)
	adapter := adapters[4]
	target := json.RawMessage(`{"kind":"space","owner":"acme","name":"demo"}`)
	if _, err := adapter.Decode(target, json.RawMessage(`{"factory_reboot":false,"token":"bad"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	input, _ := adapter.Decode(target, json.RawMessage(`{"factory_reboot":false}`))
	plan, _ := adapter.Resolve(context.Background(), input)
	client.runtime.Stage = "CHANGED"
	if _, err := adapter.Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("stale plan error = %v", err)
	}
}

type spaceFake struct {
	runtime   hubclient.SpaceRuntime
	variables map[string]hubclient.SpaceVariable
}

func (f *spaceFake) reset() {
	f.runtime = hubclient.SpaceRuntime{Stage: "RUNNING", Hardware: "cpu-basic"}
	f.variables = map[string]hubclient.SpaceVariable{}
}

func (f *spaceFake) SpaceRuntime(context.Context, hubclient.SpaceRef) (hubclient.SpaceRuntime, error) {
	return f.runtime, nil
}

func (f *spaceFake) RestartSpace(context.Context, hubclient.SpaceRef, bool) (hubclient.SpaceRuntime, error) {
	f.runtime.Stage = "RUNNING"
	return f.runtime, nil
}

func (f *spaceFake) PauseSpace(context.Context, hubclient.SpaceRef) (hubclient.SpaceRuntime, error) {
	f.runtime.Stage = "PAUSED"
	return f.runtime, nil
}

func (f *spaceFake) RequestSpaceHardware(_ context.Context, _ hubclient.SpaceRef, flavor string, sleep *int) (hubclient.SpaceRuntime, error) {
	f.runtime.RequestedHardware = flavor
	f.runtime.SleepTimeSeconds = sleep
	return f.runtime, nil
}

func (f *spaceFake) SetSpaceSleepTime(_ context.Context, _ hubclient.SpaceRef, seconds int) (hubclient.SpaceRuntime, error) {
	f.runtime.SleepTimeSeconds = &seconds
	return f.runtime, nil
}

func (f *spaceFake) SetSpaceDevMode(_ context.Context, _ hubclient.SpaceRef, enabled bool) (hubclient.SpaceRuntime, error) {
	f.runtime.DevMode = enabled
	return f.runtime, nil
}

func (f *spaceFake) SpaceVariables(context.Context, hubclient.SpaceRef) (map[string]hubclient.SpaceVariable, error) {
	copy := make(map[string]hubclient.SpaceVariable, len(f.variables))
	for key, value := range f.variables {
		copy[key] = value
	}
	return copy, nil
}

func (f *spaceFake) SetSpaceVariable(_ context.Context, _ hubclient.SpaceRef, key, value, description string) error {
	if f.variables == nil {
		return errors.New("variables unavailable")
	}
	f.variables[key] = hubclient.SpaceVariable{Value: value, Description: description}
	return nil
}

func (f *spaceFake) DeleteSpaceVariable(_ context.Context, _ hubclient.SpaceRef, key string) error {
	delete(f.variables, key)
	return nil
}
