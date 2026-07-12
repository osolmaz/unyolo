//go:build darwin

package isolation

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	bkdoctor "github.com/osolmaz/brokerkit/doctor"
)

type aclPathKind int

const (
	aclTokenEntry aclPathKind = iota
	aclSocketEntry
	aclPathParent
)

// Run evaluates the requested isolation checks on macOS.
func Run(ctx context.Context, opts Options) (Report, error) {
	if err := validateOptions(opts); err != nil {
		return Report{}, err
	}
	agent, err := resolveIdentity(opts)
	if err != nil {
		return Report{}, err
	}
	report := Report{Agent: agent.info()}
	runCredentialTargetCheck(&report, opts)
	runAgentChecks(&report, agent)
	runAgentProcChecks(&report, agent, opts.AgentPID)
	runBrokerChecks(&report, agent, opts.BrokerPID)
	runTokenFileChecks(&report, agent, opts.TokenFile)
	runSocketChecks(&report, agent, opts.Socket)
	runActiveProbeChecks(ctx, &report, agent, opts)
	report.Status = bkdoctor.OverallStatus(report.Checks)
	return report, nil
}

func runCredentialTargetCheck(report *Report, opts Options) {
	if opts.TokenFile != "" {
		add(report, CheckPass, "credential_target", "token file supplied for credential reachability checks")
		return
	}
	if opts.BrokerPID > 0 {
		add(report, CheckUnknown, "credential_target", "no token file supplied and macOS cannot inspect broker credential source without reading broker environment")
		return
	}
	add(report, CheckUnknown, "credential_target", "no token file or broker process supplied; credential reachability was not checked")
}

func resolveIdentity(opts Options) (identity, error) {
	var agent identity
	var err error
	switch {
	case opts.AgentUser != "":
		agent, err = lookupUserIdentity(opts.AgentUser, opts.AgentPID)
	case opts.AgentUIDSet:
		agent, err = lookupUIDIdentity(opts.AgentUID, opts.AgentPID)
	default:
		agent, err = resolveImplicitIdentity(opts.AgentPID)
	}
	if err != nil {
		return identity{}, err
	}
	if opts.AgentPID > 0 && opts.AgentPID != os.Getpid() {
		agent.groupsUnknown = true
	}
	return agent, nil
}

func resolveImplicitIdentity(agentPID int) (identity, error) {
	if agentPID == os.Getpid() || agentPID == 0 {
		return currentProcessIdentity(agentPID)
	}
	if agentPID > 0 {
		uid, err := processUID(agentPID)
		if err != nil {
			return identity{}, fmt.Errorf("read agent process uid: %w", err)
		}
		return lookupUIDIdentity(uid, agentPID)
	}
	return currentProcessIdentity(agentPID)
}

func currentProcessIdentity(pid int) (identity, error) {
	current, err := user.Current()
	if err != nil {
		return identity{}, fmt.Errorf("resolve current user: %w", err)
	}
	agent, err := userIdentity(current, pid)
	if err != nil {
		return identity{}, err
	}
	groups, err := os.Getgroups()
	if err != nil {
		return identity{}, fmt.Errorf("lookup current process groups: %w", err)
	}
	agent.gids = gidsMap(groups)
	agent.gids[agent.gid] = true
	agent.groups = groupNames(agent.gids)
	return agent, nil
}

func lookupUIDIdentity(uid, pid int) (identity, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return identity{uid: uid, gids: map[int]bool{}, groups: map[string]bool{}, pid: pid}, nil
	}
	return userIdentity(u, pid)
}

func runAgentProcChecks(report *Report, agent identity, pid int) {
	if pid <= 0 {
		add(report, CheckWarn, "agent_process", "no agent process supplied; process environment was not checked")
		return
	}
	uid, err := processUID(pid)
	if err != nil {
		add(report, CheckUnknown, "agent_process", "could not read agent process uid: "+err.Error())
		return
	}
	if uid != agent.uid {
		add(report, CheckFail, "agent_process_uid", fmt.Sprintf("agent process UID %d does not match configured agent UID %d", uid, agent.uid))
	} else {
		add(report, CheckPass, "agent_process_uid", "agent process UID matches configured agent identity")
	}
	add(report, CheckUnknown, "agent_env_no_hf_token", "macOS process environment names cannot be checked safely without reading process environment values")
}

func runBrokerChecks(report *Report, agent identity, pid int) {
	if pid <= 0 {
		add(report, CheckWarn, "broker_process", "no broker process supplied; broker UID was not checked")
		return
	}
	uid, err := processUID(pid)
	if err != nil {
		add(report, CheckUnknown, "broker_process", "could not read broker process uid: "+err.Error())
		return
	}
	if uid == agent.uid {
		add(report, CheckFail, "broker_separate_uid", fmt.Sprintf("broker process UID %d matches agent UID", uid))
	} else {
		add(report, CheckPass, "broker_separate_uid", fmt.Sprintf("broker UID %d differs from agent UID %d", uid, agent.uid))
	}
	add(report, CheckUnknown, "broker_env_not_readable", "macOS broker process environment readability cannot be checked safely with stdlib APIs")
}

func processUID(pid int) (int, error) {
	if pid <= 0 {
		return 0, errors.New("pid must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ps", "-o", "uid=", "-p", strconv.Itoa(pid))
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return 0, ctx.Err()
	}
	if err != nil {
		return 0, err
	}
	text := strings.TrimSpace(string(out))
	if text == "" {
		return 0, fmt.Errorf("process %d not found", pid)
	}
	uid, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("parse ps uid %q: %w", text, err)
	}
	return uid, nil
}

func runTokenACLChecks(report *Report, agent identity, path string, stat fileStat) {
	runDarwinACLChecks(
		report,
		agent,
		"token_file_acl",
		tokenACLPaths(path, stat),
		"token file path ACL grants the agent credential access outside Unix mode bits",
		"could not determine whether token file path ACLs grant credential access",
		"token file path ACLs do not grant the agent credential access outside Unix mode bits",
	)
}

func tokenACLPaths(path string, stat fileStat) []darwinACLPath {
	builder := newDarwinACLPathBuilder()
	builder.addEntryAndParents(path, aclTokenEntry)
	if bkdoctor.CleanPath(stat.path) != bkdoctor.CleanPath(path) {
		builder.addEntryAndParents(stat.path, aclTokenEntry)
	}
	if resolved, ok := bkdoctor.ResolvedCleanPath(path); ok && resolved != bkdoctor.CleanPath(path) {
		builder.addEntryAndParents(resolved, aclTokenEntry)
	}
	return builder.paths
}

func runSocketACLChecks(report *Report, agent identity, path string) {
	runDarwinACLChecks(
		report,
		agent,
		"socket_acl",
		socketACLPaths(path),
		"socket path ACL grants the agent socket access outside Unix mode bits",
		"could not determine whether socket path ACLs grant socket access",
		"socket path ACLs do not grant the agent socket access outside Unix mode bits",
	)
}

func socketACLPaths(path string) []darwinACLPath {
	builder := newDarwinACLPathBuilder()
	builder.addEntryAndParents(path, aclSocketEntry)
	if resolved, ok := bkdoctor.ResolvedCleanPath(path); ok && resolved != bkdoctor.CleanPath(path) {
		builder.addEntryAndParents(resolved, aclSocketEntry)
	}
	return builder.paths
}

type darwinACLPathBuilder struct {
	seen  map[string]bool
	paths []darwinACLPath
}

func newDarwinACLPathBuilder() darwinACLPathBuilder {
	return darwinACLPathBuilder{seen: map[string]bool{}}
}

func (b *darwinACLPathBuilder) addEntryAndParents(path string, entryKind aclPathKind) {
	b.add(path, entryKind)
	for _, dir := range bkdoctor.ParentDirs(filepath.Dir(bkdoctor.CleanPath(path))) {
		b.add(dir, aclPathParent)
	}
}

func (b *darwinACLPathBuilder) add(path string, kind aclPathKind) {
	cleaned := bkdoctor.CleanPath(path)
	key := fmt.Sprintf("%d:%s", kind, cleaned)
	if b.seen[key] {
		return
	}
	b.seen[key] = true
	b.paths = append(b.paths, darwinACLPath{path: cleaned, kind: kind})
}

type darwinACLPath struct {
	path string
	kind aclPathKind
}

func runDarwinACLChecks(report *Report, agent identity, checkName string, paths []darwinACLPath, unsafeMsg, unknownMsg, passMsg string) {
	var unknown bool
	for _, candidate := range paths {
		state := bkdoctor.DarwinACLGrantState(doctorIdentity(agent), bkdoctor.ACLPath{
			Path: candidate.path,
			Kind: bkdoctor.ACLPathKind(candidate.kind),
		})
		switch state {
		case bkdoctor.ACLPresent:
			add(report, CheckFail, checkName, unsafeMsg)
			return
		case bkdoctor.ACLUnknown:
			unknown = true
		}
	}
	if unknown {
		add(report, CheckUnknown, checkName, unknownMsg)
		return
	}
	add(report, CheckPass, checkName, passMsg)
}

func activeProbeUnavailable(opts Options) bool {
	return opts.HelperPath == "" || (opts.TokenFile == "" && opts.Socket == "")
}

func addActiveProbeResult(report *Report, opts Options, result ProbeResult) {
	if opts.TokenFile != "" {
		addActiveProbeOpenResult(report, result.TokenFileReadable, "active_probe_token_file", "the token file")
		addActiveProbeWriteResult(report, result.TokenFileWritable, "active_probe_token_file_writable", "the token file")
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
		result.BrokerEnvReadable = false
	}
	if socket != "" {
		result.SocketConnectable = dialUnixWithTimeout(socket)
	}
	return result
}
