package agentv1

import "testing"

func TestStateTerminal(t *testing.T) {
	for _, state := range []State{StateSucceeded, StateFailed, StateDenied, StateExpired, StateCanceled} {
		if !state.Terminal() {
			t.Fatalf("%s should be terminal", state)
		}
	}
	for _, state := range []State{StatePending, StateApproved, StateExecuting} {
		if state.Terminal() {
			t.Fatalf("%s should not be terminal", state)
		}
	}
}
