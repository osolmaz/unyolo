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
	"sort"
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

func lookupUserIdentity(name string, pid int) (identity, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return identity{}, fmt.Errorf("lookup agent user %q: %w", name, err)
	}
	return userIdentity(u, pid)
}

func lookupUIDIdentity(uid, pid int) (identity, error) {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return identity{uid: uid, gids: map[int]bool{}, groups: map[string]bool{}, pid: pid}, nil
	}
	return userIdentity(u, pid)
}

func userIdentity(u *user.User, pid int) (identity, error) {
	uid, gid, err := parseUserIDs(u)
	if err != nil {
		return identity{}, err
	}
	gids, groups, err := userGroupMaps(u, gid)
	if err != nil {
		return identity{}, err
	}
	return identity{user: u.Username, uid: uid, gid: gid, gidSet: true, gids: gids, groups: groups, pid: pid}, nil
}

func parseUserIDs(u *user.User) (int, int, error) {
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %q: %w", u.Username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %q: %w", u.Username, err)
	}
	return uid, gid, nil
}

func userGroupMaps(u *user.User, primaryGID int) (map[int]bool, map[string]bool, error) {
	gidValues, err := u.GroupIds()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup groups for %q: %w", u.Username, err)
	}
	gids := make(map[int]bool, len(gidValues))
	groups := map[string]bool{}
	for _, raw := range gidValues {
		gid, err := strconv.Atoi(raw)
		if err != nil {
			continue
		}
		gids[gid] = true
		if group, err := user.LookupGroupId(raw); err == nil {
			groups[group.Name] = true
		}
	}
	gids[primaryGID] = true
	if group, err := user.LookupGroupId(u.Gid); err == nil {
		groups[group.Name] = true
	}
	return gids, groups, nil
}

func (i identity) info() AgentInfo {
	gids := make([]int, 0, len(i.gids))
	for gid := range i.gids {
		gids = append(gids, gid)
	}
	sort.Ints(gids)
	groups := make([]string, 0, len(i.groups))
	for group := range i.groups {
		groups = append(groups, group)
	}
	sort.Strings(groups)
	return AgentInfo{User: i.user, UID: i.uid, GID: i.gid, GIDs: gids, Groups: groups, PID: i.pid}
}

func gidsMap(values []int) map[int]bool {
	gids := make(map[int]bool, len(values))
	for _, gid := range values {
		gids[gid] = true
	}
	return gids
}

func groupNames(gids map[int]bool) map[string]bool {
	groups := map[string]bool{}
	for gid := range gids {
		group, err := user.LookupGroupId(strconv.Itoa(gid))
		if err == nil {
			groups[group.Name] = true
		}
	}
	return groups
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

func runTokenFileChecks(report *Report, agent identity, path string) {
	if path == "" {
		add(report, CheckWarn, "token_file", "no token file supplied; file permission checks were skipped")
		return
	}
	stat, ok := tokenFileStat(report, path)
	if !ok {
		return
	}
	if canRead(agent, stat) {
		add(report, CheckFail, "token_file_not_readable", "agent can read the token file")
	} else {
		add(report, CheckPass, "token_file_not_readable", "agent cannot read the token file by Unix mode bits")
	}
	if canWrite(agent, stat) {
		add(report, CheckFail, "token_file_not_writable", "agent can modify the token file")
	} else {
		add(report, CheckPass, "token_file_not_writable", "agent cannot modify the token file by Unix mode bits")
	}
	runTokenACLChecks(report, agent, path, stat)
	runPathEntryReplaceCheck(report, agent, path, "token_file_entry_not_replaceable")
	runParentWriteChecks(report, agent, filepath.Dir(bkdoctor.CleanPath(path)), "token_file_parent_not_writable")
	runResolvedPathChecks(report, agent, path, "token_file_resolved")
}

func tokenFileStat(report *Report, path string) (fileStat, bool) {
	stat, ok := statPath(report, "token_file", path)
	if !ok {
		return fileStat{}, false
	}
	if stat.mode&os.ModeSymlink == 0 {
		return stat, true
	}
	add(report, CheckWarn, "token_file_symlink", "token file path is a symlink; checking target mode bits")
	target, ok := statTarget(path)
	if !ok {
		add(report, CheckUnknown, "token_file_target", "could not inspect token file symlink target")
		return fileStat{}, false
	}
	return target, true
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

func runSocketChecks(report *Report, agent identity, path string) {
	if path == "" {
		add(report, CheckWarn, "socket", "no Unix socket supplied; socket permission checks were skipped")
		return
	}
	stat, ok := statPath(report, "socket", path)
	if !ok {
		return
	}
	if stat.mode&os.ModeSocket == 0 {
		add(report, CheckFail, "socket_is_socket", fmt.Sprintf("%s is not a Unix socket", path))
	} else {
		add(report, CheckPass, "socket_is_socket", fmt.Sprintf("%s is a Unix socket", path))
	}
	if stat.mode.Perm()&0o002 != 0 {
		add(report, CheckFail, "socket_not_world_writable", fmt.Sprintf("socket %s is world-writable", path))
	} else {
		add(report, CheckPass, "socket_not_world_writable", fmt.Sprintf("socket %s is not world-writable", path))
	}
	if canWrite(agent, stat) {
		add(report, CheckFail, "socket_not_agent_writable", fmt.Sprintf("agent can write Unix socket %s", path))
	} else {
		add(report, CheckPass, "socket_not_agent_writable", fmt.Sprintf("agent cannot write Unix socket %s by Unix mode bits", path))
	}
	runSocketACLChecks(report, agent, path)
	runParentWriteChecks(report, agent, filepath.Dir(bkdoctor.CleanPath(path)), "socket_parent_not_writable")
	runResolvedPathChecks(report, agent, path, "socket_resolved")
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

type aclState int

const (
	aclAbsent aclState = iota
	aclPresent
	aclUnknown
)

type darwinACLEntry struct {
	principal string
	action    string
	perms     []string
}

type darwinACLPath struct {
	path string
	kind aclPathKind
}

var darwinEntryACLPerms = map[string]bool{
	"append":        true,
	"chown":         true,
	"delete":        true,
	"full_control":  true,
	"read":          true,
	"readattr":      true,
	"readextattr":   true,
	"readsecurity":  true,
	"write":         true,
	"writeattr":     true,
	"writeextattr":  true,
	"writeowner":    true,
	"writesecurity": true,
}

var darwinSocketEntryACLPerms = map[string]bool{
	"append":        true,
	"chown":         true,
	"delete":        true,
	"full_control":  true,
	"write":         true,
	"writeattr":     true,
	"writeextattr":  true,
	"writeowner":    true,
	"writesecurity": true,
}

var darwinParentACLPerms = map[string]bool{
	"add_file":         true,
	"add_subdirectory": true,
	"append":           true,
	"chown":            true,
	"delete":           true,
	"delete_child":     true,
	"full_control":     true,
	"write":            true,
	"writeattr":        true,
	"writeextattr":     true,
	"writeowner":       true,
	"writesecurity":    true,
}

var darwinACLFixedPrincipals = map[string]string{
	"everyone":  "everyone",
	"everyone@": "everyone",
	"group@":    "filegroup",
	"owner@":    "owner",
}

var darwinACLPrincipalMatchers = map[string]func(string, identity, fileStat) bool{
	"everyone":  func(_ string, _ identity, _ fileStat) bool { return true },
	"filegroup": func(_ string, agent identity, stat fileStat) bool { return agent.gids[stat.gid] },
	"group":     func(value string, agent identity, _ fileStat) bool { return darwinACLGroupApplies(value, agent) },
	"owner":     func(_ string, agent identity, stat fileStat) bool { return agent.uid == stat.uid },
	"user":      func(value string, agent identity, _ fileStat) bool { return darwinACLUserApplies(value, agent) },
}

func runDarwinACLChecks(report *Report, agent identity, checkName string, paths []darwinACLPath, unsafeMsg, unknownMsg, passMsg string) {
	var unknown bool
	for _, candidate := range paths {
		switch darwinACLState(agent, candidate) {
		case aclPresent:
			add(report, CheckFail, checkName, unsafeMsg)
			return
		case aclUnknown:
			unknown = true
		}
	}
	if unknown {
		add(report, CheckUnknown, checkName, unknownMsg)
		return
	}
	add(report, CheckPass, checkName, passMsg)
}

func darwinACLState(agent identity, candidate darwinACLPath) aclState {
	stat, ok := lstat(candidate.path)
	if !ok {
		return aclUnknown
	}
	entries, state := darwinACLEntries(candidate.path)
	if state != aclAbsent {
		return state
	}
	return darwinACLEntriesState(agent, stat, entries, candidate.kind)
}

func darwinACLEntriesState(agent identity, stat fileStat, entries []darwinACLEntry, kind aclPathKind) aclState {
	for _, entry := range entries {
		if entry.action == "deny" {
			continue
		}
		if !darwinACLEntryHasDangerousGrant(entry, kind) {
			continue
		}
		matches, ok := darwinACLAppliesToAgent(entry.principal, agent, stat)
		if !ok {
			return aclUnknown
		}
		if matches && entry.action == "allow" {
			return aclPresent
		}
	}
	return aclAbsent
}

func darwinACLEntries(path string) ([]darwinACLEntry, aclState) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/ls", "-lde", path)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	out, err := cmd.Output()
	if ctx.Err() != nil || err != nil {
		return nil, aclUnknown
	}
	return parseDarwinACLEntries(string(out))
}

func parseDarwinACLEntries(output string) ([]darwinACLEntry, aclState) {
	lines := strings.Split(output, "\n")
	var entries []darwinACLEntry
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		entry, ok := parseDarwinACLEntry(line)
		if !ok {
			return nil, aclUnknown
		}
		entries = append(entries, entry)
	}
	return entries, aclAbsent
}

func parseDarwinACLEntry(line string) (darwinACLEntry, bool) {
	body, ok := darwinACLEntryBody(line)
	if !ok {
		return darwinACLEntry{}, false
	}
	fields := strings.Fields(body)
	if len(fields) < 3 {
		return darwinACLEntry{}, false
	}
	actionIndex, ok := darwinACLActionIndex(fields)
	if !ok {
		return darwinACLEntry{}, false
	}
	principal := strings.Join(fields[:actionIndex], " ")
	perms := splitDarwinACLPerms(fields[actionIndex+1:])
	if len(perms) == 0 {
		return darwinACLEntry{}, false
	}
	return darwinACLEntry{principal: principal, action: fields[actionIndex], perms: perms}, true
}

func darwinACLEntryBody(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	indexEnd := strings.Index(trimmed, ":")
	if indexEnd <= 0 {
		return "", false
	}
	if _, err := strconv.Atoi(trimmed[:indexEnd]); err != nil {
		return "", false
	}
	return strings.TrimSpace(trimmed[indexEnd+1:]), true
}

func darwinACLActionIndex(fields []string) (int, bool) {
	for i, field := range fields {
		if field == "allow" || field == "deny" {
			return i, i > 0 && i < len(fields)-1
		}
	}
	return 0, false
}

func splitDarwinACLPerms(fields []string) []string {
	joined := strings.Join(fields, ",")
	parts := strings.Split(joined, ",")
	perms := make([]string, 0, len(parts))
	for _, part := range parts {
		perm := normalizeDarwinACLPerm(part)
		if perm == "" {
			continue
		}
		perms = append(perms, perm)
	}
	return perms
}

func normalizeDarwinACLPerm(perm string) string {
	perm = strings.TrimSpace(strings.ToLower(perm))
	perm = strings.ReplaceAll(perm, "-", "_")
	perm = strings.ReplaceAll(perm, "_security", "security")
	return perm
}

func darwinACLAppliesToAgent(principal string, agent identity, stat fileStat) (bool, bool) {
	kind, value, ok := darwinACLPrincipal(principal)
	if !ok {
		return false, false
	}
	matches, ok := darwinACLPrincipalMatchers[kind]
	if !ok {
		return false, false
	}
	return matches(value, agent, stat), true
}

func darwinACLPrincipal(principal string) (string, string, bool) {
	principal = strings.TrimSpace(principal)
	if kind, ok := darwinACLFixedPrincipals[principal]; ok {
		return kind, "", true
	}
	kind, value, ok := strings.Cut(principal, ":")
	return kind, value, ok && (kind == "user" || kind == "group")
}

func darwinACLUserApplies(value string, agent identity) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if uid, err := strconv.Atoi(value); err == nil {
		return uid == agent.uid
	}
	return value == agent.user
}

func darwinACLGroupApplies(value string, agent identity) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if value == "everyone" || value == "everyone@" {
		return true
	}
	if gid, err := strconv.Atoi(value); err == nil {
		return agent.gids[gid]
	}
	return agent.groups[value]
}

func darwinACLEntryHasDangerousGrant(entry darwinACLEntry, kind aclPathKind) bool {
	dangerous := darwinEntryACLPerms
	switch kind {
	case aclPathParent:
		dangerous = darwinParentACLPerms
	case aclSocketEntry:
		dangerous = darwinSocketEntryACLPerms
	}
	for _, perm := range entry.perms {
		if dangerous[perm] {
			return true
		}
	}
	return false
}

func runActiveProbeChecks(ctx context.Context, report *Report, agent identity, opts Options) {
	if opts.HelperPath == "" || (opts.TokenFile == "" && opts.Socket == "") {
		add(report, CheckWarn, "active_probe", "active probe skipped; no helper path or probe target supplied")
		return
	}
	result, ok, err := runActiveProbe(ctx, agent, opts)
	if err != nil {
		add(report, CheckUnknown, "active_probe", "active probe failed: "+err.Error())
		return
	}
	if !ok {
		add(report, CheckUnknown, "active_probe", "active probe could not run under the agent identity from this user")
		return
	}
	addDarwinActiveProbeResult(report, opts, result)
}

func addDarwinActiveProbeResult(report *Report, opts Options, result ProbeResult) {
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
