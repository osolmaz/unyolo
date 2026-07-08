package brokerkit

import "testing"

func TestModulePath(t *testing.T) {
	t.Parallel()
	if CanonicalModulePath() != "github.com/osolmaz/brokerkit" {
		t.Fatalf("CanonicalModulePath() = %q", CanonicalModulePath())
	}
}
