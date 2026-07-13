//go:build linux || darwin

package doctor

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sort"
	"syscall"
	"time"
)

const probeTimeout = 5 * time.Second

// ProbeCommand configures a secret-free active probe helper invocation.
type ProbeCommand struct {
	HelperPath    string
	Args          []string
	Identity      Identity
	PrimaryGIDSet bool
}

// RunProbeCommand runs a bounded helper as Identity when the current process
// is either that identity or root. The bool reports whether execution was
// possible.
func RunProbeCommand(ctx context.Context, options ProbeCommand) (ProbeResult, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	command, ok := probeCommand(ctx, options)
	if !ok {
		return ProbeResult{}, false, nil
	}
	output, err := command.Output()
	if ctx.Err() != nil {
		return ProbeResult{}, true, ctx.Err()
	}
	if err != nil {
		return ProbeResult{}, true, err
	}
	var result ProbeResult
	if err := json.Unmarshal(output, &result); err != nil {
		return ProbeResult{}, true, err
	}
	return result, true, nil
}

func probeCommand(ctx context.Context, options ProbeCommand) (*exec.Cmd, bool) {
	command := exec.CommandContext(ctx, options.HelperPath, options.Args...) // #nosec G204 -- caller supplies the installed broker helper.
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	currentUID := os.Geteuid()
	if currentUID == options.Identity.UID {
		return command, true
	}
	if currentUID == 0 && options.Identity.UID != 0 {
		command.SysProcAttr = &syscall.SysProcAttr{Credential: probeCredential(options)}
		return command, true
	}
	return nil, false
}

func probeCredential(options ProbeCommand) *syscall.Credential {
	identity := options.Identity
	groups := make([]uint32, 0, len(identity.GroupIDs))
	for _, group := range identity.GroupIDs {
		groups = append(groups, uint32(group)) // #nosec G115 -- doctor identities contain validated nonnegative Unix IDs.
	}
	sort.Slice(groups, func(left, right int) bool { return groups[left] < groups[right] })
	primary := firstProbeGroup(groups)
	if options.PrimaryGIDSet {
		primary = uint32(identity.GID) // #nosec G115 -- doctor identities contain validated nonnegative Unix IDs.
	}
	return &syscall.Credential{Uid: uint32(identity.UID), Gid: primary, Groups: groups} // #nosec G115 -- validated Unix IDs.
}

func firstProbeGroup(groups []uint32) uint32 {
	if len(groups) == 0 {
		return 0
	}
	return groups[0]
}
