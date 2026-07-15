//go:build linux || darwin

package privexec

import (
	"errors"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

type resourceLimit struct {
	resource int
	value    uint64
}

func applyLimits(value plan.Plan) error {
	return applyResourceLimits(preIdentityLimits(value))
}

func preIdentityLimits(value plan.Plan) []resourceLimit {
	return []resourceLimit{
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_NOFILE, 64},
		{unix.RLIMIT_FSIZE, uint64(value.MaxOutputBytes)},
		{unix.RLIMIT_CPU, uint64(value.TimeoutSeconds + 1)},
	}
}

func applyPostIdentityLimits() error {
	return applyResourceLimits(postIdentityLimits())
}

func postIdentityLimits() []resourceLimit { return []resourceLimit{{unix.RLIMIT_NPROC, 64}} }

func applyResourceLimits(limits []resourceLimit) error {
	for _, limit := range limits {
		if err := applyResourceLimit(limit); err != nil {
			return errors.New("apply process resource limit")
		}
	}
	return nil
}

func applyResourceLimit(limit resourceLimit) error {
	return unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: limit.value, Max: limit.value})
}
