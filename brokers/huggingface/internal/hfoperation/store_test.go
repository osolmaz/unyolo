package hfoperation

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
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
