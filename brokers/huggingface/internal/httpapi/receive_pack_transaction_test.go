package httpapi

import (
	"path/filepath"
	"testing"

	"github.com/osolmaz/unyolo/authorization/grants"
	corepolicy "github.com/osolmaz/unyolo/authorization/policy"
)

func TestHFPushTransactionRequestIDIncludesTarget(t *testing.T) {
	t.Parallel()
	server := &Server{grants: grants.New(filepath.Join(t.TempDir(), "grants.json"), grants.Options{})}
	first, err := server.hfPushTransactionRequestID("agent", "dataset/one/repo", "sha256:test", []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.hfPushTransactionRequestID("agent", "dataset/two/repo", "sha256:test", []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("request IDs collide across targets: %q", first)
	}
	result, _, err := server.grants.Request(grants.Request{Client: "agent", ClientRequestID: first, Operation: "git.push.force", Target: corepolicy.Target{Kind: "hf", Fields: map[string][]string{"name": {"dataset/one/repo"}}}, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	reused, err := server.hfPushTransactionRequestID("agent", "dataset/one/repo", "sha256:test", []string{"rule"})
	if err != nil || reused != first {
		t.Fatalf("pending request ID = %q, %v", reused, err)
	}
	if _, err := server.grants.Deny(result.Grant.ID, result.DecisionToken, "operator"); err != nil {
		t.Fatal(err)
	}
	next, err := server.hfPushTransactionRequestID("agent", "dataset/one/repo", "sha256:test", []string{"rule"})
	if err != nil || next == first {
		t.Fatalf("terminal request ID = %q, %v", next, err)
	}
}
