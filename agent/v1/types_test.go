package agentv1

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestStateValid(t *testing.T) {
	for _, state := range []State{StatePending, StateApproved, StateExecuting, StateSucceeded, StateFailed, StateDenied, StateExpired, StateCanceled} {
		if !state.Valid() {
			t.Fatalf("%s should be valid", state)
		}
	}
	for _, state := range []State{"", "unknown"} {
		if state.Valid() {
			t.Fatalf("%q should not be valid", state)
		}
	}
}

func TestStreamReferenceUsesTranscriptSafeTransferID(t *testing.T) {
	encoded, err := json.Marshal(StreamReference{TransferID: "request-1"})
	if err != nil || !strings.Contains(string(encoded), `"transfer_id":"request-1"`) || strings.Contains(string(encoded), "request_key") {
		t.Fatalf("stream reference = %s, %v", encoded, err)
	}
}

func TestValidIdempotencyKey(t *testing.T) {
	for _, value := range []string{"request", "req_1.2:3", "A"} {
		if !ValidIdempotencyKey(value) {
			t.Fatalf("valid key rejected: %q", value)
		}
	}
	for _, value := range []string{"", "bad value", "-leading", string(make([]byte, 129))} {
		if ValidIdempotencyKey(value) {
			t.Fatalf("invalid key accepted: %q", value)
		}
	}
}
