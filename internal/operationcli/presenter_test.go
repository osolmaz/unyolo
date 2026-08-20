package operationcli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/osolmaz/unyolo/agent/v1"
)

func TestDescribeStateIntentMatrix(t *testing.T) {
	t.Parallel()
	states := []agentv1.State{
		agentv1.StatePending,
		agentv1.StateApproved,
		agentv1.StateExecuting,
		agentv1.StateSucceeded,
		agentv1.StateFailed,
		agentv1.StateDenied,
		agentv1.StateExpired,
		agentv1.StateCanceled,
	}
	intents := []Intent{IntentSubmit, IntentSubmitWait, IntentGet, IntentWait}
	for _, intent := range intents {
		for _, state := range states {
			intent, state := intent, state
			t.Run(intentName(intent)+"/"+string(state), func(t *testing.T) {
				t.Parallel()
				presentation, err := Describe(intent, testOperation(state), testWaitCommand())
				if err != nil {
					t.Fatal(err)
				}
				if presentation.Notice == "" || len(presentation.Notice) > 1024 || !strings.Contains(presentation.Notice, "op_test123") {
					t.Fatalf("notice = %q", presentation.Notice)
				}
				wantFailed := expectedCommandFailure(intent, state)
				if presentation.CommandFailed != wantFailed {
					t.Fatalf("CommandFailed = %v, want %v", presentation.CommandFailed, wantFailed)
				}
				if state.Terminal() {
					if strings.Contains(presentation.Notice, "Next:") {
						t.Fatalf("terminal notice contains a next command: %q", presentation.Notice)
					}
					return
				}
				for _, text := range []string{"is not complete", "Do not report", "gh-broker operation wait --wait-timeout 15m op_test123"} {
					if !strings.Contains(presentation.Notice, text) {
						t.Fatalf("notice %q does not contain %q", presentation.Notice, text)
					}
				}
			})
		}
	}
}

func TestDescribeCancel(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		state agentv1.State
		text  string
	}{
		{state: agentv1.StateCanceled, text: "cancellation command completed"},
		{state: agentv1.StateSucceeded, text: "completed before cancellation"},
		{state: agentv1.StateFailed, text: "cancel command made no change"},
	} {
		presentation, err := Describe(IntentCancel, testOperation(test.state), nil)
		if err != nil {
			t.Fatal(err)
		}
		if presentation.CommandFailed || !strings.Contains(presentation.Notice, test.text) {
			t.Fatalf("presentation = %#v", presentation)
		}
	}
}

func TestDescribeRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		intent    Intent
		operation agentv1.Operation
		command   []string
	}{
		{name: "intent", intent: 99, operation: testOperation(agentv1.StatePending), command: testWaitCommand()},
		{name: "state", intent: IntentSubmit, operation: testOperation("unknown"), command: testWaitCommand()},
		{name: "operation ID", intent: IntentSubmit, operation: operationWithID("op_bad\ncommand"), command: []string{"wait", "op_bad\ncommand"}},
		{name: "missing wait command", intent: IntentSubmit, operation: testOperation(agentv1.StatePending)},
		{name: "wrong operation ID", intent: IntentSubmit, operation: testOperation(agentv1.StatePending), command: []string{"wait", "op_other"}},
		{name: "control in command", intent: IntentSubmit, operation: testOperation(agentv1.StatePending), command: []string{"wait\nnow", "op_test123"}},
		{name: "nonterminal cancel", intent: IntentCancel, operation: testOperation(agentv1.StateExecuting)},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Describe(test.intent, test.operation, test.command); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestDescribeDoesNotRenderOperationValues(t *testing.T) {
	t.Parallel()
	const sentinel = "SECRET-SENTINEL"
	operation := testOperation(agentv1.StateFailed)
	operation.Target = json.RawMessage(`{"value":"` + sentinel + `"}`)
	operation.Arguments = json.RawMessage(`{"value":"` + sentinel + `"}`)
	operation.Reason = sentinel
	operation.Result = json.RawMessage(`{"value":"` + sentinel + `"}`)
	operation.Error = &agentv1.OperationError{Code: "failed", Message: sentinel}
	presentation, err := Describe(IntentSubmitWait, operation, testWaitCommand())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(presentation.Notice, sentinel) {
		t.Fatalf("notice leaked operation data: %q", presentation.Notice)
	}
}

func TestWaitTimeoutArgument(t *testing.T) {
	t.Parallel()
	for duration, expected := range map[time.Duration]string{
		15 * time.Minute: "15m",
		2 * time.Hour:    "2h",
		90 * time.Second: "1m30s",
	} {
		if actual := WaitTimeoutArgument(duration); actual != expected {
			t.Fatalf("WaitTimeoutArgument(%s) = %q, want %q", duration, actual, expected)
		}
	}
}

func TestDescribeQuotesWaitCommandTokens(t *testing.T) {
	t.Parallel()
	presentation, err := Describe(IntentSubmit, testOperation(agentv1.StatePending), []string{
		"broker command", "operation", "wait", "--wait-timeout", "15m", "op_test123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(presentation.Notice, "'broker command' operation wait --wait-timeout 15m op_test123") {
		t.Fatalf("notice = %q", presentation.Notice)
	}
}

func expectedCommandFailure(intent Intent, state agentv1.State) bool {
	switch intent {
	case IntentSubmit:
		return state.Terminal() && state != agentv1.StateSucceeded
	case IntentSubmitWait, IntentWait:
		return state != agentv1.StateSucceeded
	case IntentGet:
		return false
	default:
		panic("unexpected intent")
	}
}

func intentName(intent Intent) string {
	switch intent {
	case IntentSubmit:
		return "submit"
	case IntentSubmitWait:
		return "submit-wait"
	case IntentGet:
		return "get"
	case IntentWait:
		return "wait"
	default:
		return "unknown"
	}
}

func testOperation(state agentv1.State) agentv1.Operation {
	operation := operationWithID("op_test123")
	operation.State = state
	return operation
}

func operationWithID(id string) agentv1.Operation {
	return agentv1.Operation{ID: id, State: agentv1.StatePending}
}

func testWaitCommand() []string {
	return []string{"gh-broker", "operation", "wait", "--wait-timeout", "15m", "op_test123"}
}
