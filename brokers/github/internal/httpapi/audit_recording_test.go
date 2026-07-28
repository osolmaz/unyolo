package httpapi

import (
	"testing"

	"github.com/osolmaz/unyolo/brokers/github/internal/operations"
)

func TestOperationPolicyTargetIncludesRepositoryIdentity(t *testing.T) {
	authorization := operations.Authorization{TargetKind: "issue", TargetFields: map[string][]string{
		"owner": {"osolmaz"}, "repo": {"unyolo"}, "number": {"38"},
	}}
	if got := operationPolicyTarget(authorization); got != "issue/osolmaz/unyolo/38" {
		t.Fatalf("audit target = %q", got)
	}
}
