package hfoperation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
)

func TestStoreLifecycleAndIdempotency(t *testing.T) {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := newStore(filepath.Join(t.TempDir(), "operations.json"), func() time.Time { return now }, func() (string, error) { return "op_test", nil })
	input := Submit{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "create-one", Operation: "repo.create",
		Target: json.RawMessage(`{"kind":"repo","type":"dataset","owner":"alice","name":"data"}`), Arguments: json.RawMessage(`{"private":true}`),
		Reason: "create data", Presentation: agentv1.Presentation{Title: "Create dataset", Summary: "Create alice/data"}}
	created, fresh, err := store.Submit(input)
	if err != nil || !fresh || created.State != agentv1.StatePending || created.Revision != 1 {
		t.Fatalf("submit = %#v, %v, %v", created, fresh, err)
	}
	existing, fresh, err := store.Submit(input)
	if err != nil || fresh || existing.ID != created.ID {
		t.Fatalf("idempotent submit = %#v, %v, %v", existing, fresh, err)
	}
	conflict := input
	conflict.Arguments = json.RawMessage(`{"private":false}`)
	if _, _, err := store.Submit(conflict); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if _, err := store.SetApproval(created.ID, "grant_test"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(created.ID, agentv1.StateApproved); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(created.ID, agentv1.StateExecuting); err != nil {
		t.Fatal(err)
	}
	result, err := store.Succeed(created.ID, json.RawMessage(`{"repo_id":"alice/data"}`))
	if err != nil || result.State != agentv1.StateSucceeded || result.TerminalAt == nil {
		t.Fatalf("succeed = %#v, %v", result, err)
	}
	reloaded := New(filepath.Join(filepath.Dir(store.path), "operations.json"))
	got, err := reloaded.Get("agent", created.ID)
	if err != nil || got.State != agentv1.StateSucceeded {
		t.Fatalf("reload = %#v, %v", got, err)
	}
}

func TestStoreWaitAndStrictFile(t *testing.T) {
	store := newStore(filepath.Join(t.TempDir(), "operations.json"), time.Now, func() (string, error) { return "op_wait", nil })
	op, _, err := store.Submit(Submit{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "wait", Operation: "repo.create",
		Target: json.RawMessage(`{"kind":"repo"}`), Arguments: json.RawMessage(`{}`), Presentation: agentv1.Presentation{Title: "Wait"}})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := store.Wait(ctx, "agent", op.ID, op.Revision)
	if err != nil || got.ID != op.ID {
		t.Fatalf("wait = %#v, %v", got, err)
	}
}

func TestStoreFailureListAndWaitSignal(t *testing.T) {
	store := newStore(filepath.Join(t.TempDir(), "operations.json"), time.Now, func() (string, error) { return "op_signal", nil })
	op, _, err := store.Submit(validSubmit("signal"))
	if err != nil {
		t.Fatal(err)
	}
	unfinished, err := store.ListUnfinished()
	if err != nil || len(unfinished) != 1 {
		t.Fatalf("unfinished = %#v, %v", unfinished, err)
	}
	result := make(chan agentv1.Operation, 1)
	go func() {
		got, _ := store.Wait(context.Background(), "agent", op.ID, op.Revision)
		result <- got
	}()
	failed, err := store.Fail(op.ID, agentv1.StateDenied, "denied", "operator denied")
	if err != nil || failed.State != agentv1.StateDenied || failed.Error == nil {
		t.Fatalf("fail = %#v, %v", failed, err)
	}
	select {
	case got := <-result:
		if got.State != agentv1.StateDenied {
			t.Fatalf("wait state = %s", got.State)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not wake")
	}
	unfinished, err = store.ListUnfinished()
	if err != nil || len(unfinished) != 0 {
		t.Fatalf("terminal unfinished = %#v, %v", unfinished, err)
	}
	if _, err := store.Fail(op.ID, agentv1.StateSucceeded, "bad", "bad"); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("invalid failure state = %v", err)
	}
	if _, err := store.Transition(op.ID, agentv1.StateApproved); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal transition = %v", err)
	}
}

func TestStoreRejectsInvalidInputsAndState(t *testing.T) {
	store := New(filepath.Join(t.TempDir(), "operations.json"))
	invalid := []Submit{
		{},
		{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "one", Operation: "repo.create", Target: json.RawMessage(`[]`), Arguments: json.RawMessage(`{}`), Presentation: agentv1.Presentation{Title: "Create"}},
		{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "one", Operation: "repo.create", Target: json.RawMessage(`{"a":1,"a":2}`), Arguments: json.RawMessage(`{}`), Presentation: agentv1.Presentation{Title: "Create"}},
		{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: "one", Operation: "repo.create", Target: json.RawMessage(`{}`), Arguments: json.RawMessage(`{}`), Presentation: agentv1.Presentation{}},
	}
	for index, input := range invalid {
		if _, _, err := store.Submit(input); err == nil {
			t.Fatalf("invalid input %d accepted", index)
		}
	}
	if _, err := store.Get("agent", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing get = %v", err)
	}
	if _, err := store.Succeed("missing", json.RawMessage(`[]`)); err == nil {
		t.Fatal("invalid result accepted")
	}
	if _, err := store.Fail("missing", agentv1.StateFailed, "", ""); err == nil {
		t.Fatal("invalid error accepted")
	}
}

func TestStoreRejectsCorruptFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.json")
	store := New(path)
	cases := []string{
		`{"version":2,"operations":[]}`,
		`{"version":1,"version":1,"operations":[]}`,
		`{"version":1,"operations":[]} trailing`,
		`{"version":1,"unknown":true,"operations":[]}`,
		`{"version":1,"operations":[{"api_version":"wrong"}]}`,
	}
	for _, data := range cases {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListUnfinished(); err == nil {
			t.Fatalf("corrupt file accepted: %s", data)
		}
	}
}

func TestRandomIDAndValidationHelpers(t *testing.T) {
	id, err := randomID()
	if err != nil || !strings.HasPrefix(id, "op_") || len(id) < 20 {
		t.Fatalf("random ID = %q, %v", id, err)
	}
	if validState(agentv1.State("unknown")) {
		t.Fatal("unknown state accepted")
	}
	if validOperationError(&agentv1.OperationError{}) {
		t.Fatal("empty operation error accepted")
	}
	if equalJSON([]byte(`{`), []byte(`{}`)) {
		t.Fatal("invalid JSON compared equal")
	}
}

func validSubmit(key string) Submit {
	return Submit{Broker: "hf-broker", ClientID: "agent", IdempotencyKey: key, Operation: "repo.create",
		Target: json.RawMessage(`{"kind":"repo","type":"dataset","owner":"alice","name":"data"}`), Arguments: json.RawMessage(`{"private":true}`),
		Reason: "create data", Presentation: agentv1.Presentation{Title: "Create dataset", Summary: "Create alice/data"}}
}
