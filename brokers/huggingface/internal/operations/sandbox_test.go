package operations

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/hubclient"
	hfpolicy "github.com/osolmaz/brokerkit/brokers/huggingface/internal/policy"
	"github.com/osolmaz/brokerkit/brokers/huggingface/internal/sealedstore"
)

func TestSandboxAdaptersRegisterEveryExecutionOperation(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	adapters, err := NewSandboxAdapters(&sandboxFake{}, store)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := NewRegistry(adapters...)
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Names()) != len(sandboxOperations) {
		t.Fatalf("sandbox adapter count = %d, want %d", len(registry.Names()), len(sandboxOperations))
	}
	for _, operation := range sandboxOperations {
		if _, found := registry.Lookup(operation); !found {
			t.Fatalf("sandbox operation %q is not registered", operation)
		}
	}
}

func TestSandboxCreateConsumesSealedSecretsWithoutLeakingThemIntoPlan(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	reference, err := store.Put("bob", "sandbox.create", []byte(`{"secrets":{"API_TOKEN":"canary-secret"}}`), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	client := &sandboxFake{identity: "operator"}
	adapters, _ := NewSandboxAdapters(client, store)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("sandbox.create")
	arguments, _ := json.Marshal(sealedBoundArguments{Public: json.RawMessage(`{"image":"python:3.12","flavor":"cpu-basic","idle_timeout_seconds":600,"environment":{"MODE":"test"}}`), SealedPayload: &reference})
	input, err := adapter.Decode(json.RawMessage(`{"kind":"sandbox","namespace":"acme","name":"review"}`), arguments)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.(ClientBoundAdapter).ValidateClient(input, "bob"); err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil || bytes.Contains(plan.Arguments, []byte("canary-secret")) || strings.Contains(plan.Presentation.Summary, "canary-secret") {
		t.Fatalf("Resolve() = %+v, %v", plan, err)
	}
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || client.created.Secrets["API_TOKEN"] != "canary-secret" || client.created.Secrets["MODE"] != "" {
		t.Fatalf("Execute() = %+v, %v; spec=%+v", outcome, err, client.created)
	}
	if _, err := store.Get(reference); err == nil {
		t.Fatal("sealed sandbox payload remained after execution")
	}
}

func TestSandboxCommandPresentationIsExactAndStaleStateFailsClosed(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	client := &sandboxFake{identity: "operator", state: runningSandboxState()}
	adapters, _ := NewSandboxAdapters(client, store)
	registry, _ := NewRegistry(adapters...)
	adapter, _ := registry.Lookup("sandbox.command.run")
	input, err := adapter.Decode(existingSandboxTarget(), json.RawMessage(`{"argv":["echo","hi"],"max_output_bytes":4096}`))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.Resolve(context.Background(), input)
	if err != nil || !strings.Contains(plan.Presentation.Summary, `["echo","hi"]`) {
		t.Fatalf("Resolve() = %+v, %v", plan, err)
	}
	client.state.Image = "changed:latest"
	if _, err := adapter.Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "precondition") {
		t.Fatalf("stale command plan error = %v", err)
	}
	client.state = runningSandboxState()
	plan, _ = adapter.Resolve(context.Background(), input)
	outcome, err := adapter.Execute(context.Background(), plan)
	if err != nil || !outcome.Proven || len(client.command.Argv) != 2 {
		t.Fatalf("Execute() = %+v, %v; command=%+v", outcome, err, client.command)
	}
}

func TestSandboxAdaptersUseClosedOperationSpecificInputs(t *testing.T) {
	store, _ := sealedstore.Open(t.TempDir())
	adapters, _ := NewSandboxAdapters(&sandboxFake{}, store)
	registry, _ := NewRegistry(adapters...)
	tests := []struct {
		operation string
		target    json.RawMessage
		arguments json.RawMessage
	}{
		{"sandbox.command.run", existingSandboxTarget(), json.RawMessage(`{"shell_command":"echo hi","max_output_bytes":4096}`)},
		{"sandbox.delete", existingSandboxTarget(), json.RawMessage(`{}`)},
		{"sandbox.file.delete", existingSandboxTarget(), json.RawMessage(`{"path":"/tmp/result","recursive":false}`)},
		{"sandbox.file.mkdir", existingSandboxTarget(), json.RawMessage(`{"path":"/tmp/output"}`)},
		{"sandbox.file.write", existingSandboxTarget(), json.RawMessage(`{"path":"/tmp/result","content_base64":"aGk=","mode":"0644"}`)},
		{"sandbox.pool.create", json.RawMessage(`{"kind":"sandbox_pool","namespace":"acme","name":"workers"}`), json.RawMessage(`{"public":{"image":"python:3.12","flavor":"cpu-basic","sandboxes_per_host":10,"warm_up":1,"max_hosts":2,"idle_timeout_seconds":600}}`)},
		{"sandbox.pool.delete", json.RawMessage(`{"kind":"sandbox_pool","namespace":"acme","name":"workers"}`), json.RawMessage(`{}`)},
		{"sandbox.pool.warm", json.RawMessage(`{"kind":"sandbox_pool","namespace":"acme","name":"workers"}`), json.RawMessage(`{"num_hosts":2}`)},
		{"sandbox.process.kill", existingSandboxTarget(), json.RawMessage(`{"pid":12}`)},
	}
	for _, test := range tests {
		adapter, _ := registry.Lookup(test.operation)
		if _, err := adapter.Decode(test.target, test.arguments); err != nil {
			t.Errorf("%s valid input rejected: %v", test.operation, err)
		}
		var unknown map[string]any
		_ = json.Unmarshal(test.arguments, &unknown)
		unknown["unregistered"] = true
		invalid, _ := json.Marshal(unknown)
		if _, err := adapter.Decode(test.target, invalid); err == nil {
			t.Errorf("%s accepted an unknown argument field", test.operation)
		}
	}
}

func TestSandboxAdaptersExecuteEveryOperationLifecycle(t *testing.T) {
	poolHost := runningSandboxState()
	poolHost.Mode = "pool"
	poolHost.Pool = "workers"
	poolHost.Capacity = 10
	poolHost.MaxHosts = 3

	tests := []struct {
		operation string
		target    json.RawMessage
		arguments json.RawMessage
		configure func(*sandboxFake)
	}{
		{"sandbox.command.run", existingSandboxTarget(), json.RawMessage(`{"argv":["echo","hi"],"max_output_bytes":4096}`), nil},
		{"sandbox.create", json.RawMessage(`{"kind":"sandbox","namespace":"acme","name":"review"}`), json.RawMessage(`{"public":{"image":"python:3.12","flavor":"cpu-basic","environment":{"MODE":"test"}}}`), nil},
		{"sandbox.create", json.RawMessage(`{"kind":"sandbox","namespace":"acme","name":"pooled","pool":"workers"}`), json.RawMessage(`{"public":{"environment":{"MODE":"test"}}}`), func(fake *sandboxFake) {
			fake.pool = []hubclient.SandboxState{poolHost}
		}},
		{"sandbox.delete", existingSandboxTarget(), json.RawMessage(`{}`), nil},
		{"sandbox.file.write", existingSandboxTarget(), json.RawMessage(`{"path":"/tmp/result","content_base64":"aGk=","mode":"0644"}`), nil},
		{"sandbox.file.mkdir", existingSandboxTarget(), json.RawMessage(`{"path":"/tmp/output"}`), nil},
		{"sandbox.file.delete", existingSandboxTarget(), json.RawMessage(`{"path":"/tmp/result","recursive":false}`), func(fake *sandboxFake) {
			fake.file = hubclient.SandboxFileInfo{Name: "result", Path: "/tmp/result", Type: "file", Size: 2, Mode: "0644"}
		}},
		{"sandbox.process.kill", existingSandboxTarget(), json.RawMessage(`{"pid":12}`), func(fake *sandboxFake) {
			fake.processes = []hubclient.SandboxProcess{{PID: 12, Command: []string{"sleep", "60"}, Running: true}}
		}},
		{"sandbox.pool.create", json.RawMessage(`{"kind":"sandbox_pool","namespace":"acme","name":"workers"}`), json.RawMessage(`{"public":{"image":"python:3.12","flavor":"cpu-basic","sandboxes_per_host":10,"warm_up":1,"max_hosts":3}}`), nil},
		{"sandbox.pool.warm", json.RawMessage(`{"kind":"sandbox_pool","namespace":"acme","name":"workers"}`), json.RawMessage(`{"num_hosts":2}`), func(fake *sandboxFake) {
			fake.pool = []hubclient.SandboxState{poolHost}
		}},
		{"sandbox.pool.delete", json.RawMessage(`{"kind":"sandbox_pool","namespace":"acme","name":"workers"}`), json.RawMessage(`{}`), func(fake *sandboxFake) {
			fake.pool = []hubclient.SandboxState{poolHost}
		}},
	}

	for _, test := range tests {
		t.Run(test.operation, func(t *testing.T) {
			store, err := sealedstore.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			client := &sandboxFake{identity: "operator", state: runningSandboxState()}
			if test.configure != nil {
				test.configure(client)
			}
			adapters, err := NewSandboxAdapters(client, store)
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewRegistry(adapters...)
			if err != nil {
				t.Fatal(err)
			}
			adapter, found := registry.Lookup(test.operation)
			if !found {
				t.Fatal("adapter is not registered")
			}
			input, err := adapter.Decode(test.target, test.arguments)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := adapter.Resolve(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if request := adapter.Authorize(Plan{Target: plan.Target, Arguments: plan.Arguments}); request.Operation != hfpolicy.Operation(test.operation) {
				t.Fatalf("Authorize() operation = %q", request.Operation)
			}
			if presentation := adapter.Present(Plan{Target: plan.Target, Arguments: plan.Arguments}); presentation.Title == "" {
				t.Fatal("Present() returned an empty title")
			}
			outcome, err := adapter.Execute(context.Background(), plan)
			if err != nil || !outcome.Proven {
				t.Fatalf("Execute() = %+v, %v", outcome, err)
			}
			reconciled, err := adapter.Reconcile(context.Background(), plan)
			wantReconciled := test.operation != "sandbox.command.run" && test.operation != "sandbox.file.write" && !bytes.Contains(test.target, []byte(`"pool":"workers"`))
			if err != nil || reconciled.Proven != wantReconciled {
				t.Fatalf("Reconcile() = %+v, %v; want proven=%v", reconciled, err, wantReconciled)
			}
		})
	}
}

type sandboxFake struct {
	identity           string
	state              hubclient.SandboxState
	pool               []hubclient.SandboxState
	created            hubclient.SandboxCreateSpec
	command            hubclient.SandboxCommand
	file               hubclient.SandboxFileInfo
	processes          []hubclient.SandboxProcess
	createdByOperation []hubclient.SandboxState
}

func (f *sandboxFake) WhoAmI(context.Context) (hubclient.Identity, error) {
	if f.identity == "" {
		f.identity = "operator"
	}
	return hubclient.Identity{Name: f.identity}, nil
}

func (f *sandboxFake) SandboxState(context.Context, hubclient.SandboxRef) (hubclient.SandboxState, error) {
	if f.state.Ref.JobID == "" {
		f.state = runningSandboxState()
	}
	return f.state, nil
}

func (f *sandboxFake) ListSandboxPool(context.Context, hubclient.SandboxPoolRef) ([]hubclient.SandboxState, error) {
	return append([]hubclient.SandboxState(nil), f.pool...), nil
}

func (f *sandboxFake) ListSandboxesByOperation(context.Context, string, string) ([]hubclient.SandboxState, error) {
	return append([]hubclient.SandboxState(nil), f.createdByOperation...), nil
}

func (f *sandboxFake) CreateSandbox(_ context.Context, spec hubclient.SandboxCreateSpec) (hubclient.SandboxState, error) {
	f.created = spec
	state := runningSandboxState()
	f.createdByOperation = append(f.createdByOperation, state)
	return state, nil
}

func (f *sandboxFake) CreateSandboxPoolHost(context.Context, hubclient.SandboxPoolSpec) (hubclient.SandboxState, error) {
	state := runningSandboxState()
	f.createdByOperation = append(f.createdByOperation, state)
	return state, nil
}

func (f *sandboxFake) CreateSandboxInPool(context.Context, hubclient.SandboxRef, map[string]string, *int) (hubclient.SandboxRef, error) {
	return hubclient.SandboxRef{Namespace: "acme", JobID: "687fb701029421ae5549d998", LocalID: "local"}, nil
}

func (f *sandboxFake) DeleteSandbox(context.Context, hubclient.SandboxRef) error {
	f.state.Stage = "DELETED"
	return nil
}

func (f *sandboxFake) CancelSandboxJob(context.Context, hubclient.SandboxRef) error {
	f.pool = nil
	return nil
}

func (f *sandboxFake) RunSandboxCommand(_ context.Context, _ hubclient.SandboxRef, command hubclient.SandboxCommand) (hubclient.SandboxCommandResult, error) {
	f.command = command
	exitCode := 0
	return hubclient.SandboxCommandResult{ExitCode: &exitCode, Stdout: "hi\n"}, nil
}

func (f *sandboxFake) SandboxFileStat(context.Context, hubclient.SandboxRef, string) (hubclient.SandboxFileInfo, error) {
	if f.file.Path == "" {
		return hubclient.SandboxFileInfo{}, &hubclient.Error{Code: hubclient.CodeNotFound, StatusCode: 404}
	}
	return f.file, nil
}

func (f *sandboxFake) WriteSandboxFile(context.Context, hubclient.SandboxRef, string, string, []byte) error {
	return nil
}

func (f *sandboxFake) MakeSandboxDirectory(_ context.Context, _ hubclient.SandboxRef, path string) error {
	f.file = hubclient.SandboxFileInfo{Name: "output", Path: path, Type: "dir", Mode: "0755"}
	return nil
}

func (f *sandboxFake) DeleteSandboxFile(context.Context, hubclient.SandboxRef, string, bool) error {
	f.file = hubclient.SandboxFileInfo{}
	return nil
}

func (f *sandboxFake) SandboxProcesses(context.Context, hubclient.SandboxRef) ([]hubclient.SandboxProcess, error) {
	return append([]hubclient.SandboxProcess(nil), f.processes...), nil
}

func (f *sandboxFake) KillSandboxProcess(context.Context, hubclient.SandboxRef, int) error {
	for index := range f.processes {
		f.processes[index].Running = false
	}
	return nil
}

func runningSandboxState() hubclient.SandboxState {
	return hubclient.SandboxState{Ref: hubclient.SandboxRef{Namespace: "acme", JobID: "687fb701029421ae5549d998"},
		Image: "python:3.12", Flavor: "cpu-basic", Stage: "RUNNING", Mode: "dedicated"}
}

func existingSandboxTarget() json.RawMessage {
	return json.RawMessage(`{"kind":"sandbox","namespace":"acme","job_id":"687fb701029421ae5549d998"}`)
}

var _ sandboxClient = (*sandboxFake)(nil)
