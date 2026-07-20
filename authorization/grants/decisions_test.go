package grants

import (
	"errors"
	"testing"
)

func TestDecisionTokenMatchesRejectsEmptyValues(t *testing.T) {
	verifier := decisionTokenVerifier("token")
	if decisionTokenMatches("", "token") {
		t.Fatal("decisionTokenMatches() accepted an empty verifier")
	}
	if decisionTokenMatches(verifier, "") {
		t.Fatal("decisionTokenMatches() accepted an empty presented token")
	}
}

func TestTerminalDecisionReturnsNoGrant(t *testing.T) {
	store := New(t.TempDir()+"/grants.json", Options{})
	result := requestTestGrant(t, store, "terminal-decision-result", 1)
	if _, err := store.Approve(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.Deny(result.Grant.ID, result.DecisionToken, "operator")
	if !errors.Is(err, ErrNotPending) || replayed.ID != "" {
		t.Fatalf("Deny(terminal) = %+v err=%v, want empty grant and ErrNotPending", replayed, err)
	}
}
