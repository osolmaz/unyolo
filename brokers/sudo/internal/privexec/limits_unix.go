//go:build linux || darwin

package privexec

import (
	"errors"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
	"golang.org/x/sys/unix"
)

func applyLimits(value plan.Plan) error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_CORE, 0},
		{unix.RLIMIT_NOFILE, 64},
		{unix.RLIMIT_NPROC, 64},
		{unix.RLIMIT_FSIZE, uint64(value.MaxOutputBytes)},
		{unix.RLIMIT_CPU, uint64(value.TimeoutSeconds + 1)},
	}
	for _, limit := range limits {
		if err := unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: limit.value, Max: limit.value}); err != nil {
			return errors.New("apply process resource limit")
		}
	}
	return nil
}
