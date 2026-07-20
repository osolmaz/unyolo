package httpapi

import (
	"path/filepath"
	"testing"

	"github.com/osolmaz/brokerkit/authorization/grants"
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
}
