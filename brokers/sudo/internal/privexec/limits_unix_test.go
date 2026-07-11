//go:build linux || darwin

package privexec

import (
	"testing"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

func TestProcessLimitIsAppliedAfterIdentityTransition(t *testing.T) {
	t.Parallel()
	for _, limit := range preIdentityLimits(plan.Plan{TimeoutSeconds: 5, MaxOutputBytes: 1024}) {
		if limit.resource == unix.RLIMIT_NPROC {
			t.Fatal("RLIMIT_NPROC was applied before the UID transition")
		}
	}
	limits := postIdentityLimits()
	if len(limits) != 1 || limits[0].resource != unix.RLIMIT_NPROC || limits[0].value != 64 {
		t.Fatalf("post-identity limits = %+v", limits)
	}
}
