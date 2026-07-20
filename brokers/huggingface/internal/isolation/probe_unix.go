//go:build linux || darwin

package isolation

import (
	"context"
	"strconv"

	bkdoctor "github.com/osolmaz/brokerkit/internal/host/doctor"
)

func runActiveProbe(ctx context.Context, agent identity, opts Options) (ProbeResult, bool, error) {
	return bkdoctor.RunProbeCommand(ctx, bkdoctor.ProbeCommand{
		HelperPath:    opts.HelperPath,
		Args:          activeProbeArgs(opts),
		Identity:      doctorIdentity(agent),
		PrimaryGIDSet: agent.gidSet,
	})
}

func activeProbeArgs(opts Options) []string {
	args := []string{"__doctor-isolation-probe"}
	if opts.TokenFile != "" {
		args = append(args, "--token-file", opts.TokenFile)
	}
	if opts.BrokerPID > 0 {
		args = append(args, "--broker-pid", strconv.Itoa(opts.BrokerPID))
	}
	if opts.Socket != "" {
		args = append(args, "--socket", opts.Socket)
	}
	return args
}
