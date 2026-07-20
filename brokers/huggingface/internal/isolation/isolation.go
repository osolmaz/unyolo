//go:build linux

package isolation

import (
	"context"
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	bkdoctor "github.com/osolmaz/brokerkit/internal/host/doctor"
)

type procStatus = bkdoctor.ProcessStatus

// Run evaluates the requested isolation checks.
func Run(ctx context.Context, opts Options) (Report, error) {
	if err := validateOptions(opts); err != nil {
		return Report{}, err
	}
	agent, err := resolveIdentity(opts)
	if err != nil {
		return Report{}, err
	}
	processStatus, processStatusErr := readOptionalAgentProcessStatus(opts.AgentPID)
	accessAgent := accessIdentity(agent, processStatus, processStatusErr)
	report := Report{Agent: accessAgent.info()}
	runCredentialTargetCheck(&report, opts)
	runAgentChecks(&report, accessAgent)
	runAgentProcChecks(&report, agent, opts.AgentPID, processStatus, processStatusErr)
	runBrokerChecks(&report, accessAgent, opts.BrokerPID)
	runTokenFileChecks(&report, accessAgent, opts.TokenFile)
	runSocketChecks(&report, accessAgent, opts.Socket)
	runActiveProbeChecks(ctx, &report, accessAgent, opts)
	report.Status = bkdoctor.OverallStatus(report.Checks)
	report.Credentials = credentialStatuses(opts)
	return report, nil
}

func runCredentialTargetCheck(report *Report, opts Options) {
	if opts.TokenFile != "" && opts.BrokerPID <= 0 {
		add(report, CheckPass, "credential_target", "token file supplied for credential reachability checks")
		return
	}
	if opts.BrokerPID <= 0 {
		add(report, CheckUnknown, "credential_target", "no token file or broker process supplied; credential reachability was not checked")
		return
	}
	env, err := readProcEnviron(opts.BrokerPID)
	cwd, cwdErr := readProcCWD(opts.BrokerPID)
	addBrokerEnvCredentialTargetCheck(report, opts.TokenFile, env, err, cwd, cwdErr)
}

func addBrokerEnvCredentialTargetCheck(report *Report, tokenFile string, env []string, err error, brokerCWD string, brokerCWDErr error) {
	if err != nil {
		if tokenFile != "" {
			add(report, CheckUnknown, "credential_target", "token file supplied but broker credential source could not be checked")
			return
		}
		add(report, CheckUnknown, "credential_target", "no token file supplied and broker credential source could not be checked")
		return
	}
	if brokerTokenFile, ok := envValue(env, "HF_BROKER_HF_TOKEN_FILE"); ok {
		addBrokerTokenFileCredentialTargetCheck(report, tokenFile, brokerTokenFile, brokerCWD, brokerCWDErr)
		return
	}
	if envHasName(env, "HF_BROKER_HF_TOKEN") {
		add(report, CheckPass, "credential_target", "broker environment token source supplied for credential reachability checks")
		return
	}
	add(report, CheckUnknown, "credential_target", "no token file supplied and broker credential source was not identifiable")
}

func addBrokerTokenFileCredentialTargetCheck(report *Report, tokenFile, brokerTokenFile, brokerCWD string, brokerCWDErr error) {
	if tokenFile == "" {
		add(report, CheckUnknown, "credential_target", "broker uses a token file but --token-file was not supplied")
		return
	}
	if brokerCWDErr != nil && !filepath.IsAbs(brokerTokenFile) {
		add(report, CheckUnknown, "credential_target", "broker uses a token file but broker working directory could not be checked")
		return
	}
	same, ok := sameCredentialPath(tokenFile, brokerTokenFile, brokerCWD)
	if !ok {
		add(report, CheckUnknown, "credential_target", "broker token file path could not be resolved")
		return
	}
	if !same {
		add(report, CheckUnknown, "credential_target", "checked token file does not match broker token file")
		return
	}
	add(report, CheckPass, "credential_target", "checked token file matches broker credential source")
}

func readOptionalAgentProcessStatus(pid int) (*procStatus, error) {
	if pid <= 0 {
		return nil, nil
	}
	status, err := readProcStatus(pid)
	if err != nil {
		return nil, err
	}
	return &status, nil
}

func resolveIdentity(opts Options) (identity, error) {
	if opts.AgentUser != "" {
		return lookupUserIdentity(opts.AgentUser, opts.AgentPID)
	}
	return resolveIdentityWithoutUser(opts)
}

func resolveIdentityWithoutUser(opts Options) (identity, error) {
	if opts.AgentUIDSet {
		return lookupUIDIdentity(opts.AgentUID, opts.AgentPID)
	}
	return resolveImplicitIdentity(opts.AgentPID)
}

func resolveImplicitIdentity(agentPID int) (identity, error) {
	if agentPID > 0 {
		status, err := readProcStatus(agentPID)
		if err != nil {
			return identity{}, fmt.Errorf("read agent process status: %w", err)
		}
		return lookupUIDIdentity(status.FilesystemUID, agentPID)
	}
	current, err := user.Current()
	if err != nil {
		return identity{}, fmt.Errorf("resolve current user: %w", err)
	}
	return userIdentity(current, agentPID)
}

func lookupUIDIdentity(uid, pid int) (identity, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err == nil {
		return userIdentity(u, pid)
	}
	if pid <= 0 {
		return identity{}, fmt.Errorf("lookup agent UID %d: not found; pass --agent-pid to derive runtime groups", uid)
	}
	return identity{uid: uid, gids: map[int]bool{}, groups: map[string]bool{}, pid: pid}, nil
}

func identityWithProcessStatus(agent identity, status procStatus) identity {
	agent.uid = status.FilesystemUID
	agent.gid = status.FilesystemGID
	agent.gidSet = true
	agent.gids = gidsMap(status.Groups)
	for _, gid := range status.GIDs {
		agent.gids[gid] = true
	}
	agent.groups = groupNames(agent.gids)
	return agent
}

func accessIdentity(agent identity, status *procStatus, statusErr error) identity {
	if statusErr != nil || status == nil || !status.AllUIDsMatch(agent.uid) {
		return agent
	}
	return identityWithProcessStatus(agent, *status)
}

func runAgentProcChecks(report *Report, agent identity, pid int, status *procStatus, statusErr error) {
	if pid <= 0 {
		add(report, CheckWarn, "agent_process", "no agent process supplied; process capabilities and env were not checked")
		return
	}
	if statusErr != nil {
		add(report, CheckUnknown, "agent_process", "could not read agent process status: "+statusErr.Error())
		return
	}
	if !status.AllUIDsMatch(agent.uid) {
		add(report, CheckFail, "agent_process_uid", fmt.Sprintf("agent process UIDs %v do not all match configured agent UID %d", status.UIDs, agent.uid))
	} else {
		add(report, CheckPass, "agent_process_uid", "agent process UID matches configured agent identity")
	}
	runCapabilityCheck(report, status.EffectiveCaps|status.PermittedCaps)
	runAgentEnvCheck(report, pid)
}

func runCapabilityCheck(report *Report, capEff uint64) {
	found := bkdoctor.RootEquivalentCapabilityNames(capEff, 0)
	if len(found) > 0 {
		add(report, CheckFail, "agent_capabilities", "agent process has root-equivalent capability bits: "+strings.Join(found, ", "))
		return
	}
	add(report, CheckPass, "agent_capabilities", "agent process has no known root-equivalent effective capabilities")
}

func runAgentEnvCheck(report *Report, pid int) {
	env, err := readProcEnviron(pid)
	if err != nil {
		add(report, CheckUnknown, "agent_env_no_hf_token", "could not read agent process env names: "+err.Error())
		return
	}
	if envHasSecretName(env) {
		add(report, CheckFail, "agent_env_no_hf_token", "agent process environment contains an HF token variable name")
		return
	}
	add(report, CheckPass, "agent_env_no_hf_token", "agent process environment has no HF token variable names")
}

func runBrokerChecks(report *Report, agent identity, pid int) {
	if pid <= 0 {
		add(report, CheckWarn, "broker_process", "no broker process supplied; broker UID and broker env readability were not checked")
		return
	}
	status, err := readProcStatus(pid)
	if err != nil {
		add(report, CheckUnknown, "broker_process", "could not read broker process status: "+err.Error())
		return
	}
	if status.HasUID(agent.uid) {
		add(report, CheckFail, "broker_separate_uid", fmt.Sprintf("broker process includes agent UID %d", agent.uid))
	} else {
		add(report, CheckPass, "broker_separate_uid", fmt.Sprintf("broker UIDs %v differ from agent UID %d", status.UIDs, agent.uid))
	}
}

func runTokenACLChecks(report *Report, _ identity, path string, stat fileStat) {
	var unknown bool
	for _, candidate := range tokenACLPaths(path, stat) {
		switch bkdoctor.PathACLState(candidate) {
		case bkdoctor.ACLPresent:
			add(report, CheckUnknown, "token_file_acl", "token file or parent directory uses POSIX ACLs; Unix mode checks are incomplete")
			return
		case bkdoctor.ACLUnknown:
			unknown = true
		case bkdoctor.ACLAbsent:
		}
	}
	if unknown {
		add(report, CheckUnknown, "token_file_acl", "could not determine whether token file path uses POSIX ACLs")
		return
	}
	add(report, CheckPass, "token_file_acl", "token file path has no POSIX ACLs affecting mode-bit checks")
}

func tokenACLPaths(path string, stat fileStat) []string {
	seen := make(map[string]bool)
	var paths []string
	addPath := func(candidate string) {
		cleaned := bkdoctor.CleanPath(candidate)
		if seen[cleaned] {
			return
		}
		seen[cleaned] = true
		paths = append(paths, cleaned)
	}
	addPath(path)
	for _, dir := range bkdoctor.ParentDirs(filepath.Dir(bkdoctor.CleanPath(path))) {
		addPath(dir)
	}
	if bkdoctor.CleanPath(stat.path) != bkdoctor.CleanPath(path) {
		addPath(stat.path)
		for _, dir := range bkdoctor.ParentDirs(filepath.Dir(bkdoctor.CleanPath(stat.path))) {
			addPath(dir)
		}
	}
	if resolved, ok := bkdoctor.ResolvedCleanPath(path); ok && resolved != bkdoctor.CleanPath(path) {
		addPath(resolved)
		for _, dir := range bkdoctor.ParentDirs(filepath.Dir(resolved)) {
			addPath(dir)
		}
	}
	return paths
}

func runSocketACLChecks(report *Report, _ identity, path string) {
	var unknown bool
	for _, candidate := range socketACLPaths(path) {
		switch bkdoctor.PathACLState(candidate) {
		case bkdoctor.ACLPresent:
			add(report, CheckUnknown, "socket_acl", "socket or parent directory uses POSIX ACLs; Unix mode checks are incomplete")
			return
		case bkdoctor.ACLUnknown:
			unknown = true
		case bkdoctor.ACLAbsent:
		}
	}
	if unknown {
		add(report, CheckUnknown, "socket_acl", "could not determine whether socket path uses POSIX ACLs")
		return
	}
	add(report, CheckPass, "socket_acl", "socket path has no POSIX ACLs affecting mode-bit checks")
}

func socketACLPaths(path string) []string {
	seen := make(map[string]bool)
	var paths []string
	addPath := func(candidate string) {
		cleaned := bkdoctor.CleanPath(candidate)
		if seen[cleaned] {
			return
		}
		seen[cleaned] = true
		paths = append(paths, cleaned)
	}
	addPath(path)
	for _, dir := range bkdoctor.ParentDirs(filepath.Dir(bkdoctor.CleanPath(path))) {
		addPath(dir)
	}
	if resolved, ok := bkdoctor.ResolvedCleanPath(path); ok && resolved != bkdoctor.CleanPath(path) {
		addPath(resolved)
		for _, dir := range bkdoctor.ParentDirs(filepath.Dir(resolved)) {
			addPath(dir)
		}
	}
	return paths
}

func activeProbeUnavailable(opts Options) bool {
	return opts.HelperPath == "" || opts.TokenFile == "" && opts.BrokerPID <= 0 && opts.Socket == ""
}

func addActiveProbeResult(report *Report, opts Options, result ProbeResult) {
	if opts.TokenFile != "" {
		addActiveProbeOpenResult(report, result.TokenFileReadable, "active_probe_token_file", "the token file")
		addActiveProbeWriteResult(report, result.TokenFileWritable, "active_probe_token_file_writable", "the token file")
	}
	if opts.BrokerPID > 0 {
		addActiveProbeOpenResult(report, result.BrokerEnvReadable, "active_probe_broker_env", "broker /proc environ")
	}
	if opts.Socket != "" {
		addActiveProbeOpenResult(report, result.SocketConnectable, "active_probe_socket_connect", "the Unix socket")
	}
}

func RunProbe(tokenFile string, brokerPID int, socket string) ProbeResult {
	var result ProbeResult
	if tokenFile != "" {
		result.TokenFileReadable = bkdoctor.CanOpen(tokenFile)
		result.TokenFileWritable = bkdoctor.CanOpenForWrite(tokenFile)
	}
	if brokerPID > 0 {
		result.BrokerEnvReadable = bkdoctor.CanOpen(procPath(brokerPID, "environ"))
	}
	if socket != "" {
		result.SocketConnectable = bkdoctor.DialUnix(context.Background(), socket)
	}
	return result
}
