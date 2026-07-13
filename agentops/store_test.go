package agentops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/osolmaz/brokerkit/agentv1"
	"github.com/osolmaz/brokerkit/plandigest"
	"github.com/osolmaz/brokerkit/state"
)

func TestStoreLifecycleAndIdempotency(t *testing.T) {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := newTestStore(t, func() time.Time { return now }, func() (string, error) { return "op_test", nil })
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
	reloaded := New(store.db)
	got, err := reloaded.Get("agent", created.ID)
	if err != nil || got.State != agentv1.StateSucceeded {
		t.Fatalf("reload = %#v, %v", got, err)
	}
	byID, err := reloaded.GetByID(created.ID)
	if err != nil || byID.ID != created.ID {
		t.Fatalf("get by ID = %#v, %v", byID, err)
	}
	byKey, err := reloaded.GetByIdempotency("agent", "create-one")
	if err != nil || byKey.ID != created.ID {
		t.Fatalf("get by idempotency = %#v, %v", byKey, err)
	}
}

func TestStoreAcceptsPreallocatedOperationID(t *testing.T) {
	store := newTestStore(t, time.Now, func() (string, error) { return "op_generated", nil })
	input := validSubmit("preallocated")
	input.ID = "op_preallocated"
	operation, created, err := store.Submit(input)
	if err != nil || !created || operation.ID != input.ID {
		t.Fatalf("Submit() = %+v, %v, %v", operation, created, err)
	}
	if _, _, err := store.Submit(Submit{ID: "invalid", Broker: "hf-broker"}); err == nil {
		t.Fatal("invalid preallocated ID accepted")
	}
	if id, err := store.NewID(); err != nil || id != "op_generated" {
		t.Fatalf("NewID() = %q, %v", id, err)
	}
}

func TestStoreWaitAndStrictFile(t *testing.T) {
	store := newTestStore(t, time.Now, func() (string, error) { return "op_wait", nil })
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

func TestStoreCancelIsOwnedIdempotentAndStopsAtExecution(t *testing.T) {
	store := newTestStore(t, time.Now, func() (string, error) { return "op_cancel", nil })
	operation, _, err := store.Submit(validSubmit("cancel"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cancel("other", operation.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-client cancel = %v", err)
	}
	canceled, err := store.Cancel("agent", operation.ID)
	if err != nil || canceled.State != agentv1.StateCanceled || canceled.Error == nil {
		t.Fatalf("cancel = %#v, %v", canceled, err)
	}
	revision := canceled.Revision
	replayed, err := store.Cancel("agent", operation.ID)
	if err != nil || replayed.Revision != revision {
		t.Fatalf("cancel replay = %#v, %v", replayed, err)
	}
	executingInput := validSubmit("executing")
	executingInput.ID = "op_executing"
	executing, _, _ := store.Submit(executingInput)
	_, _ = store.Transition(executing.ID, agentv1.StateApproved)
	_, _ = store.Transition(executing.ID, agentv1.StateExecuting)
	if _, err := store.Cancel("agent", executing.ID); !errors.Is(err, ErrNotCancelable) {
		t.Fatalf("executing cancel = %v", err)
	}
}

func TestStoreAcceptsBoundedCommandResult(t *testing.T) {
	store := newTestStore(t, time.Now, func() (string, error) { return "op_output", nil })
	operation, _, err := store.Submit(validSubmit("output"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(operation.ID, agentv1.StateApproved); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(operation.ID, agentv1.StateExecuting); err != nil {
		t.Fatal(err)
	}
	result := json.RawMessage(`{"stdout_base64":"` + strings.Repeat("a", 1024*1024) + `"}`)
	if completed, err := store.Succeed(operation.ID, result); err != nil || completed.State != agentv1.StateSucceeded {
		t.Fatalf("large result = %#v, %v", completed, err)
	}
}

func TestStorePersistsOperationAndImmutablePlanAtomically(t *testing.T) {
	now := time.Date(2026, 7, 13, 8, 0, 0, 0, time.UTC)
	store := newTestStore(t, func() time.Time { return now }, func() (string, error) { return "op_plan", nil })
	canonical := []byte(`{"api_version":"provider.io/plan/v1","operation":"repo.delete"}`)
	plan := state.PlanRecord{Digest: plandigest.Digest(canonical), SchemaName: "provider.io/plan/v1", Canonical: canonical, CreatedAt: now}
	created, fresh, err := store.SubmitWithPlan(validSubmit("planned"), plan)
	if err != nil || !fresh || created.PlanDigest != plan.Digest {
		t.Fatalf("SubmitWithPlan() = %+v, %v, %v", created, fresh, err)
	}
	replayed, fresh, err := store.SubmitWithPlan(validSubmit("planned"), plan)
	if err != nil || fresh || replayed.PlanDigest != plan.Digest {
		t.Fatalf("planned replay = %+v, %v, %v", replayed, fresh, err)
	}

	otherCanonical := []byte(`{"api_version":"provider.io/plan/v1","operation":"repo.move"}`)
	other := state.PlanRecord{Digest: plandigest.Digest(otherCanonical), SchemaName: plan.SchemaName, Canonical: otherCanonical, CreatedAt: now}
	if _, _, err := store.SubmitWithPlan(validSubmit("planned"), other); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("plan replay conflict = %v", err)
	}
	if _, _, err := store.SubmitWithPlan(validSubmit("invalid-plan"), state.PlanRecord{}); err == nil {
		t.Fatal("invalid immutable plan accepted")
	}
	if count, err := store.db.CountOperations(t.Context()); err != nil || count != 1 {
		t.Fatalf("operations after plan rollback = %d, %v", count, err)
	}
}

func TestStoreAcceptsManifestAndCanonicalReasonBounds(t *testing.T) {
	store := newTestStore(t, time.Now, func() (string, error) { return "op_manifest", nil })
	input := validSubmit("manifest")
	input.Arguments = json.RawMessage(`{"manifest":"` + strings.Repeat("a", 64*1024) + `"}`)
	input.Reason = strings.Repeat("r", 2000)
	if _, _, err := store.Submit(input); err != nil {
		t.Fatalf("bounded manifest rejected: %v", err)
	}
	tooLong := validSubmit("reason-too-long")
	tooLong.Reason = strings.Repeat("r", 2001)
	if _, _, err := store.Submit(tooLong); err == nil {
		t.Fatal("overlong reason accepted")
	}
	largeTarget := validSubmit("target-too-large")
	largeTarget.Target = json.RawMessage(`{"value":"` + strings.Repeat("a", maxTargetBytes) + `"}`)
	if _, _, err := store.Submit(largeTarget); err == nil {
		t.Fatal("oversized target accepted")
	}
}

func TestStoreFailureListAndWaitSignal(t *testing.T) {
	store := newTestStore(t, time.Now, func() (string, error) { return "op_signal", nil })
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
	store := newTestStore(t, time.Now, randomID)
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

func TestStoreBoundsAndPrunesOperations(t *testing.T) {
	now := time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)
	store := newTestStore(t, func() time.Time { return now }, func() (string, error) { return "op_new", nil })
	operations := make([]agentv1.Operation, maxOperations)
	for index := range operations {
		operations[index] = validOperationForStore(fmt.Sprintf("op_%d", index), agentv1.StatePending, now)
		if err := store.db.InsertOperation(t.Context(), operationRecord(operations[index])); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.Submit(validSubmit("full")); !errors.Is(err, ErrCapacity) {
		t.Fatalf("full store error = %v", err)
	}
	operations[0] = validOperationForStore("op_0", agentv1.StateSucceeded, now.Add(-terminalRetention-time.Hour))
	terminalAt := operations[0].UpdatedAt
	operations[0].TerminalAt = &terminalAt
	operations[0].Result = json.RawMessage(`{"repo_id":"alice/old"}`)
	operations[0].Revision = 2
	if updated, err := store.db.UpdateOperation(t.Context(), operationRecord(operations[0]), 1); err != nil || !updated {
		t.Fatalf("mark terminal = %v, %v", updated, err)
	}
	created, fresh, err := store.Submit(validSubmit("after-prune"))
	if err != nil || !fresh || created.ID != "op_new" {
		t.Fatalf("submit after prune = %#v, %v, %v", created, fresh, err)
	}
}

func TestStoredLifecycleRejectsCorruptState(t *testing.T) {
	now := time.Date(2026, 7, 13, 6, 0, 0, 0, time.UTC)
	valid := validOperationForStore("op", agentv1.StatePending, now)
	tests := []struct {
		name   string
		mutate func(*agentv1.Operation)
	}{
		{name: "terminal timestamp", mutate: func(operation *agentv1.Operation) { operation.TerminalAt = &now }},
		{name: "state", mutate: func(operation *agentv1.Operation) { operation.State = agentv1.State("invalid") }},
		{name: "approval", mutate: func(operation *agentv1.Operation) { operation.ApprovalID = strings.Repeat("a", 129) }},
		{name: "error", mutate: func(operation *agentv1.Operation) { operation.Error = &agentv1.OperationError{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			operation := valid
			test.mutate(&operation)
			if err := validateStoredLifecycle(operation); err == nil {
				t.Fatal("validateStoredLifecycle() accepted corrupt state")
			}
		})
	}
}

func newTestStore(t *testing.T, now func() time.Time, newID func() (string, error)) *Store {
	t.Helper()
	database, err := state.Open(t.Context(), t.TempDir(), state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return newStore(database, now, newID)
}

func validOperationForStore(id string, state agentv1.State, updated time.Time) agentv1.Operation {
	operation := agentv1.Operation{
		APIVersion: agentv1.APIVersion, ID: id, Broker: "hf-broker", ClientID: "agent", IdempotencyKey: id,
		Operation: "repo.create", Target: json.RawMessage(`{"kind":"repo"}`), Arguments: json.RawMessage(`{"private":true}`),
		State: state, Revision: 1, CreatedAt: updated, UpdatedAt: updated, Presentation: agentv1.Presentation{Title: "Create"},
	}
	return operation
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
