package httpapi

import (
	"testing"

	corepolicy "github.com/osolmaz/brokerkit/authorization/policy"
)

func TestGitTransactionRequestIDIncludesTarget(t *testing.T) {
	t.Parallel()
	server := newTestServer(t)
	attrs := map[string][]string{"plan_digest": {"sha256:test"}}
	first, err := server.gitTransactionRequestID("bob", corepolicy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"one"}, "name": {"repo"}}}, attrs, []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := server.gitTransactionRequestID("bob", corepolicy.Target{Kind: "repo", Fields: map[string][]string{"owner": {"two"}, "name": {"repo"}}}, attrs, []string{"rule"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatalf("request IDs collide across targets: %q", first)
	}
}
