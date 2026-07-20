//go:build linux || darwin

package isolation

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	bkdoctor "github.com/osolmaz/brokerkit/internal/host/doctor"
)

func validateOptions(opts Options) error {
	if opts.AgentUIDSet && opts.AgentUser != "" {
		return errors.New("--agent-user and --agent-uid are mutually exclusive")
	}
	if opts.AgentPID < 0 {
		return errors.New("--agent-pid must be non-negative")
	}
	if opts.BrokerPID < 0 {
		return errors.New("--broker-pid must be non-negative")
	}
	return nil
}

func runAgentChecks(report *Report, agent identity) {
	if agent.uid == 0 {
		add(report, CheckFail, "agent_not_root", "agent UID is 0; host root can read local credentials and bypass broker isolation")
	} else {
		add(report, CheckPass, "agent_not_root", fmt.Sprintf("agent UID %d is not root", agent.uid))
	}
	var risky []string
	for group := range agent.groups {
		if bkdoctor.RootEquivalentGroup(group) {
			risky = append(risky, group)
		}
	}
	sort.Strings(risky)
	if len(risky) > 0 {
		add(report, CheckFail, "agent_not_root_equivalent_group", "agent is in root-equivalent group(s): "+strings.Join(risky, ", "))
		return
	}
	if agent.groupsUnknown {
		add(report, CheckUnknown, "agent_not_root_equivalent_group", "agent process supplementary groups could not be checked safely on macOS")
		return
	}
	add(report, CheckPass, "agent_not_root_equivalent_group", "agent is not in a known root-equivalent group")
}
