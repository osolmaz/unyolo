//go:build darwin

package privexec

import (
	"errors"
	"syscall"

	"github.com/osolmaz/brokerkit/brokers/sudo/internal/hostcheck"
	"github.com/osolmaz/brokerkit/brokers/sudo/internal/plan"
)

func executePlan(value plan.Plan) error {
	if err := applyLimits(value); err != nil {
		return err
	}
	if err := hostcheck.ValidateExecution(value, ^uint32(0)); err != nil {
		return err
	}
	groups := make([]int, len(value.SupplementaryGIDs))
	for index, group := range value.SupplementaryGIDs {
		groups[index] = int(group)
	}
	if err := syscall.Chdir(value.WorkingDirectory); err != nil {
		return errors.New("enter working directory")
	}
	if err := syscall.Setgroups(groups); err != nil {
		return errors.New("drop supplementary groups")
	}
	if err := syscall.Setgid(int(value.TargetGID)); err != nil {
		return errors.New("drop target gid")
	}
	if err := syscall.Setuid(int(value.TargetUID)); err != nil {
		return errors.New("drop target uid")
	}
	argv := append([]string{value.Executable}, value.Arguments...)
	return syscall.Exec(value.Executable, argv, append([]string(nil), value.Environment...))
}
