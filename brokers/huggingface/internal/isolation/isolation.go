//go:build linux

package isolation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	bkdoctor "github.com/osolmaz/brokerkit/doctor"
)

type identity struct {
	user   string
	uid    int
	gid    int
	gidSet bool
	gids   map[int]bool
	groups map[string]bool
	pid    int
}

type fileStat struct {
	path string
	mode os.FileMode
	uid  int
	gid  int
}

type procStatus struct {
	uid       int
	gid       int
	uidValues []int
	gidValues []int
	gids      []int
	capEff    uint64
	capPrm    uint64
}

type parentFailure int

const (
	parentWritable parentFailure = iota
	parentSymlinkReplace
)

type pathKind int

const (
	pathKindTokenFile pathKind = iota
	pathKindSocket
)

type pathMessageSet struct {
	entryLabel     string
	resolveUnknown string
	parentPass     string
}

var pathMessages = map[pathKind]pathMessageSet{
	pathKindTokenFile: {
		entryLabel:     "token-file",
		resolveUnknown: "could not resolve token-file path",
		parentPass:     "agent cannot write checked token-file parent directories",
	},
	pathKindSocket: {
		entryLabel:     "socket",
		resolveUnknown: "could not resolve socket path",
		parentPass:     "agent cannot write checked parent directories",
	},
}

var dangerousCapabilities = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	19: "CAP_SYS_PTRACE",
	21: "CAP_SYS_ADMIN",
	31: "CAP_SETFCAP",
}

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
	report.Status = overallStatus(report.Checks)
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
		return lookupUIDIdentity(status.uid, agentPID)
	}
	current, err := user.Current()
	if err != nil {
		return identity{}, fmt.Errorf("resolve current user: %w", err)
	}
	return userIdentity(current, agentPID)
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
	if err == nil {
		return userIdentity(u, pid)
	}
	if pid <= 0 {
		return identity{}, fmt.Errorf("lookup agent UID %d: not found; pass --agent-pid to derive runtime groups", uid)
	}
	return identity{uid: uid, gids: map[int]bool{}, groups: map[string]bool{}, pid: pid}, nil
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

func identityWithProcessStatus(agent identity, status procStatus) identity {
	agent.uid = status.uid
	agent.gid = status.gid
	agent.gidSet = true
	agent.gids = gidsMap(status.gids)
	for _, gid := range status.gidValues {
		agent.gids[gid] = true
	}
	agent.groups = groupNames(agent.gids)
	return agent
}

func accessIdentity(agent identity, status *procStatus, statusErr error) identity {
	if statusErr != nil || status == nil || !status.allUIDsMatch(agent.uid) {
		return agent
	}
	return identityWithProcessStatus(agent, *status)
}

func (s procStatus) allUIDsMatch(uid int) bool {
	return allIntsMatch(s.uidValues, uid)
}

func (s procStatus) hasUID(uid int) bool {
	for _, value := range s.uidValues {
		if value == uid {
			return true
		}
	}
	return false
}

func allIntsMatch(values []int, want int) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if value != want {
			return false
		}
	}
	return true
}

func intsString(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, strconv.Itoa(value))
	}
	return "[" + strings.Join(parts, " ") + "]"
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
	add(report, CheckPass, "agent_not_root_equivalent_group", "agent is not in a known root-equivalent group")
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
	if !status.allUIDsMatch(agent.uid) {
		add(report, CheckFail, "agent_process_uid", fmt.Sprintf("agent process UIDs %s do not all match configured agent UID %d", intsString(status.uidValues), agent.uid))
	} else {
		add(report, CheckPass, "agent_process_uid", "agent process UID matches configured agent identity")
	}
	runCapabilityCheck(report, status.capEff|status.capPrm)
	runAgentEnvCheck(report, pid)
}

func runCapabilityCheck(report *Report, capEff uint64) {
	var found []string
	for bit, name := range dangerousCapabilities {
		if capEff&(uint64(1)<<bit) != 0 {
			found = append(found, name)
		}
	}
	sort.Strings(found)
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
	if status.hasUID(agent.uid) {
		add(report, CheckFail, "broker_separate_uid", fmt.Sprintf("broker process includes agent UID %d", agent.uid))
	} else {
		add(report, CheckPass, "broker_separate_uid", fmt.Sprintf("broker UIDs %s differ from agent UID %d", intsString(status.uidValues), agent.uid))
	}
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
	runTokenACLChecks(report, path, stat)
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

func runTokenACLChecks(report *Report, path string, stat fileStat) {
	var unknown bool
	for _, candidate := range tokenACLPaths(path, stat) {
		switch posixACLState(candidate) {
		case aclPresent:
			add(report, CheckUnknown, "token_file_acl", "token file or parent directory uses POSIX ACLs; Unix mode checks are incomplete")
			return
		case aclUnknown:
			unknown = true
		case aclAbsent:
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
	runSocketACLChecks(report, path)
	runParentWriteChecks(report, agent, filepath.Dir(bkdoctor.CleanPath(path)), "socket_parent_not_writable")
	runResolvedPathChecks(report, agent, path, "socket_resolved")
}

func runSocketACLChecks(report *Report, path string) {
	var unknown bool
	for _, candidate := range socketACLPaths(path) {
		switch posixACLState(candidate) {
		case aclPresent:
			add(report, CheckUnknown, "socket_acl", "socket or parent directory uses POSIX ACLs; Unix mode checks are incomplete")
			return
		case aclUnknown:
			unknown = true
		case aclAbsent:
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

func runParentWriteChecks(report *Report, agent identity, dir, name string) {
	dirs := bkdoctor.ParentDirs(dir)
	for _, candidate := range dirs {
		stat, ok := lstat(candidate)
		if !ok {
			add(report, CheckUnknown, name, parentInspectMessage(name, candidate))
			return
		}
		if stat.mode&os.ModeSymlink != 0 {
			if runParentSymlinkReplaceCheck(report, agent, stat, name) {
				return
			}
			continue
		}
		if canReplaceDirectoryEntry(agent, stat) {
			add(report, CheckFail, name, parentFailureMessage(name, candidate, parentWritable))
			return
		}
	}
	add(report, CheckPass, name, parentPassMessage(name))
}

func runParentSymlinkReplaceCheck(report *Report, agent identity, entry fileStat, name string) bool {
	parent, parentOK := lstat(filepath.Dir(entry.path))
	if !parentOK {
		add(report, CheckUnknown, name, parentInspectMessage(name, filepath.Dir(entry.path)))
		return true
	}
	if canReplacePathEntry(agent, entry, parent) {
		add(report, CheckFail, name, parentFailureMessage(name, entry.path, parentSymlinkReplace))
		return true
	}
	return false
}

func runPathEntryReplaceCheck(report *Report, agent identity, path, name string) {
	entry, entryOK := lstat(bkdoctor.CleanPath(path))
	if !entryOK {
		add(report, CheckUnknown, name, pathEntryInspectMessage(name))
		return
	}
	parent, parentOK := lstat(bkdoctor.ResolvedDir(path))
	if !parentOK {
		add(report, CheckUnknown, name, pathEntryParentInspectMessage(name))
		return
	}
	if canReplacePathEntry(agent, entry, parent) {
		add(report, CheckFail, name, pathEntryReplaceMessage(name))
		return
	}
	add(report, CheckPass, name, pathEntryPassMessage(name))
}

func runResolvedPathChecks(report *Report, agent identity, path, prefix string) {
	resolved, ok := bkdoctor.ResolvedCleanPath(path)
	if !ok {
		add(report, CheckUnknown, prefix+"_path", pathMessagesFor(prefix).resolveUnknown)
		return
	}
	if resolved == bkdoctor.CleanPath(path) {
		return
	}
	runPathEntryReplaceCheck(report, agent, resolved, prefix+"_entry_not_replaceable")
	runParentWriteChecks(report, agent, filepath.Dir(resolved), prefix+"_parent_not_writable")
}

func pathEntryInspectMessage(name string) string {
	return "could not inspect " + pathMessagesFor(name).entryLabel + " directory entry"
}

func pathEntryParentInspectMessage(name string) string {
	return "could not inspect " + pathMessagesFor(name).entryLabel + " entry parent directory"
}

func pathEntryReplaceMessage(name string) string {
	return "agent can replace the " + pathMessagesFor(name).entryLabel + " directory entry"
}

func pathEntryPassMessage(name string) string {
	return "agent cannot replace the " + pathMessagesFor(name).entryLabel + " directory entry"
}

func pathMessagesFor(name string) pathMessageSet {
	if strings.HasPrefix(name, "socket") {
		return pathMessages[pathKindSocket]
	}
	return pathMessages[pathKindTokenFile]
}

func parentInspectMessage(name, path string) string {
	if strings.HasPrefix(name, "token_file") {
		return "could not inspect a token-file parent directory"
	}
	return "could not inspect parent directory " + path
}

func parentFailureMessage(name, path string, failure parentFailure) string {
	if strings.HasPrefix(name, "token_file") && failure == parentWritable {
		return "agent can write a token-file parent directory"
	}
	if strings.HasPrefix(name, "token_file") {
		return "agent can replace a symlinked token-file parent directory entry"
	}
	if failure == parentWritable {
		return fmt.Sprintf("agent can write parent directory %s", path)
	}
	return fmt.Sprintf("agent can replace symlinked parent directory entry %s", path)
}

func parentPassMessage(name string) string {
	return pathMessagesFor(name).parentPass
}

func runActiveProbeChecks(ctx context.Context, report *Report, agent identity, opts Options) {
	if activeProbeUnavailable(opts) {
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
	addActiveProbeResult(report, opts, result)
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

func addActiveProbeOpenResult(report *Report, readable bool, checkName, target string) {
	if readable {
		add(report, CheckFail, checkName, "agent process successfully opened "+target)
		return
	}
	add(report, CheckPass, checkName, "agent process could not open "+target)
}

func addActiveProbeWriteResult(report *Report, writable bool, checkName, target string) {
	if writable {
		add(report, CheckFail, checkName, "agent process successfully opened "+target+" for writing")
		return
	}
	add(report, CheckPass, checkName, "agent process could not open "+target+" for writing")
}

func statPath(report *Report, checkName, path string) (fileStat, bool) {
	if !filepath.IsAbs(path) {
		add(report, CheckWarn, checkName+"_absolute", relativePathMessage(checkName, path))
	}
	stat, ok := lstat(bkdoctor.CleanPath(path))
	if !ok {
		add(report, CheckUnknown, checkName, inspectPathMessage(checkName, path))
		return fileStat{}, false
	}
	return stat, true
}

func relativePathMessage(checkName, path string) string {
	if checkName == "token_file" {
		return "token file path is relative; absolute paths are safer for deployment checks"
	}
	return fmt.Sprintf("%s is relative; absolute paths are safer for deployment checks", path)
}

func inspectPathMessage(checkName, path string) string {
	if checkName == "token_file" {
		return "could not inspect token file"
	}
	return "could not inspect " + path
}

func lstat(path string) (fileStat, bool) {
	return statFile(path, false)
}

func statTarget(path string) (fileStat, bool) {
	target, err := filepath.EvalSymlinks(bkdoctor.CleanPath(path))
	if err != nil {
		return fileStat{}, false
	}
	return statFile(target, true)
}

func statFile(path string, followSymlink bool) (fileStat, bool) {
	info, err := lstatOrStat(path, followSymlink)
	if err != nil {
		return fileStat{}, false
	}
	raw, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileStat{}, false
	}
	return fileStat{path: path, mode: info.Mode(), uid: int(raw.Uid), gid: int(raw.Gid)}, true
}

func lstatOrStat(path string, followSymlink bool) (os.FileInfo, error) {
	if followSymlink {
		return os.Stat(path)
	}
	return os.Lstat(path)
}

type aclState int

const (
	aclAbsent aclState = iota
	aclPresent
	aclUnknown
)

func posixACLState(path string) aclState {
	return maxACLState(
		xattrState(path, "system.posix_acl_access"),
		xattrState(path, "system.posix_acl_default"),
	)
}

func xattrState(path, name string) aclState {
	_, err := syscall.Getxattr(path, name, nil)
	if err == nil || errors.Is(err, syscall.ERANGE) {
		return aclPresent
	}
	if errors.Is(err, syscall.ENODATA) || errors.Is(err, syscall.ENOTSUP) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, os.ErrNotExist) {
		return aclAbsent
	}
	return aclUnknown
}

func maxACLState(a, b aclState) aclState {
	if a == aclPresent || b == aclPresent {
		return aclPresent
	}
	if a == aclUnknown || b == aclUnknown {
		return aclUnknown
	}
	return aclAbsent
}

func add(report *Report, status CheckStatus, name, message string) {
	report.Checks = append(report.Checks, Check{Status: status, Name: name, Message: message})
}

func overallStatus(checks []Check) Status {
	var unknown bool
	for _, check := range checks {
		switch check.Status {
		case CheckFail:
			return StatusUnsafe
		case CheckUnknown:
			unknown = true
		case CheckPass, CheckWarn:
		}
	}
	if unknown {
		return StatusInconclusive
	}
	return StatusOK
}

// RunProbe performs active checks from the current process identity.
func RunProbe(tokenFile string, brokerPID int, socket string) ProbeResult {
	var result ProbeResult
	if tokenFile != "" {
		result.TokenFileReadable = canOpen(tokenFile)
		result.TokenFileWritable = canOpenForWrite(tokenFile)
	}
	if brokerPID > 0 {
		result.BrokerEnvReadable = canOpen(procPath(brokerPID, "environ"))
	}
	if socket != "" {
		result.SocketConnectable = DialUnix(context.Background(), socket)
	}
	return result
}

func canOpen(path string) bool {
	file, err := os.Open(path) // #nosec G304 -- operator-supplied local path for an isolation probe.
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func canOpenForWrite(path string) bool {
	file, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- operator-supplied local path for an isolation probe.
	if err != nil {
		return false
	}
	_ = file.Close()
	return true
}

func runActiveProbe(ctx context.Context, agent identity, opts Options) (ProbeResult, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd, ok := activeProbeCommand(ctx, agent, opts)
	if !ok {
		return ProbeResult{}, false, nil
	}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return ProbeResult{}, true, ctx.Err()
	}
	if err != nil {
		return ProbeResult{}, true, err
	}
	var result ProbeResult
	if err := json.Unmarshal(out, &result); err != nil {
		return ProbeResult{}, true, err
	}
	return result, true, nil
}

func activeProbeCommand(ctx context.Context, agent identity, opts Options) (*exec.Cmd, bool) {
	cmd := exec.CommandContext(ctx, opts.HelperPath, activeProbeArgs(opts)...) // #nosec G204 -- helper path is os.Executable from the CLI.
	cmd.Env = activeProbeEnv()
	currentUID := os.Geteuid()
	if currentUID == agent.uid {
		return cmd, true
	}
	if currentUID == 0 && agent.uid != 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: agent.credential()}
		return cmd, true
	}
	return nil, false
}

func activeProbeEnv() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C"}
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

func (i identity) credential() *syscall.Credential {
	groups := i.credentialGroups()
	return &syscall.Credential{Uid: uint32(i.uid), Gid: i.primaryCredentialGroup(groups), Groups: groups} // #nosec G115 -- resolved Unix IDs are validated nonnegative kernel IDs.
}

func (i identity) credentialGroups() []uint32 {
	groups := make([]uint32, 0, len(i.gids))
	for gid := range i.gids {
		groups = append(groups, uint32(gid)) // #nosec G115 -- resolved Unix group IDs are validated nonnegative kernel IDs.
	}
	sort.Slice(groups, func(a, b int) bool { return groups[a] < groups[b] })
	return groups
}

func (i identity) primaryCredentialGroup(groups []uint32) uint32 {
	if i.gidSet {
		return uint32(i.gid) // #nosec G115 -- resolved Unix group IDs are validated nonnegative kernel IDs.
	}
	return firstCredentialGroup(groups)
}

func firstCredentialGroup(groups []uint32) uint32 {
	if len(groups) == 0 {
		return 0
	}
	return groups[0]
}

// DialUnix reports whether the current process can connect to socket. It is
// kept small for future doctor checks and tests.
func DialUnix(ctx context.Context, socket string) bool {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socket)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
