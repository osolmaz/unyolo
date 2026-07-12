// Package doctor provides secret-safe local broker isolation checks.
package doctor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/osolmaz/brokerkit/internal/validatex"
)

// Status is the overall doctor verdict.
type Status string

const (
	StatusOK           Status = "ok"
	StatusUnsafe       Status = "unsafe"
	StatusInconclusive Status = "inconclusive"
)

// CheckStatus is one check result.
type CheckStatus string

const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckWarn    CheckStatus = "warn"
	CheckUnknown CheckStatus = "unknown"
)

// Identity is a local Unix account and its supplementary groups.
type Identity struct {
	User       string   `json:"user"`
	UID        int      `json:"uid"`
	GID        int      `json:"gid"`
	GroupIDs   []int    `json:"group_ids,omitempty"`
	GroupNames []string `json:"groups,omitempty"`
}

// Check is one stable, secret-safe doctor result.
type Check struct {
	Status  CheckStatus `json:"status"`
	Name    string      `json:"name"`
	Message string      `json:"message"`
}

// Report is a portable doctor report.
type Report struct {
	Status Status   `json:"status"`
	Agent  Identity `json:"agent"`
	Checks []Check  `json:"checks"`
}

var lookupGroupByID = user.LookupGroupId

// LookupIdentity resolves a local account and all group memberships.
func LookupIdentity(name string) (Identity, error) {
	account, err := user.Lookup(strings.TrimSpace(name))
	if err != nil {
		return Identity{}, fmt.Errorf("lookup agent user: %w", err)
	}
	uid, err := numericID("agent uid", account.Uid)
	if err != nil {
		return Identity{}, err
	}
	gid, err := numericID("agent gid", account.Gid)
	if err != nil {
		return Identity{}, err
	}
	groupIDs, groupNames, err := identityGroups(account)
	if err != nil {
		return Identity{}, err
	}
	return Identity{User: account.Username, UID: uid, GID: gid, GroupIDs: groupIDs, GroupNames: groupNames}, nil
}

func numericID(label string, value string) (int, error) {
	id, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", label, err)
	}
	return id, nil
}

func identityGroups(account *user.User) ([]int, []string, error) {
	groupIDs, err := account.GroupIds()
	if err != nil {
		return nil, nil, fmt.Errorf("list agent groups: %w", err)
	}
	ids := make([]int, 0, len(groupIDs))
	names := make([]string, 0, len(groupIDs))
	for _, value := range groupIDs {
		groupID, parseErr := numericID("agent group id", value)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		ids = append(ids, groupID)
		group, lookupErr := lookupGroupByID(value)
		if lookupErr != nil {
			return nil, nil, fmt.Errorf("lookup agent group %s: %w", value, lookupErr)
		}
		names = append(names, group.Name)
	}
	sort.Ints(ids)
	sort.Strings(names)
	return ids, names, nil
}

// RootEquivalentCheck rejects root and groups that commonly grant a path to
// unrestricted host privilege.
func RootEquivalentCheck(identity Identity) Check {
	if identity.UID == 0 {
		return Check{Status: CheckFail, Name: "agent_not_root_equivalent", Message: "agent uid is root"}
	}
	if identity.GID == 0 || slices.Contains(identity.GroupIDs, 0) {
		return Check{Status: CheckFail, Name: "agent_not_root_equivalent", Message: "agent belongs to root group id 0"}
	}
	for _, group := range identity.GroupNames {
		if RootEquivalentGroup(group) {
			return Check{Status: CheckFail, Name: "agent_not_root_equivalent", Message: "agent belongs to root-equivalent group " + group}
		}
	}
	return Check{Status: CheckPass, Name: "agent_not_root_equivalent", Message: "agent is not root and has no known root-equivalent group"}
}

// RootEquivalentGroup reports whether a group commonly grants unrestricted
// host privilege on Linux or macOS.
func RootEquivalentGroup(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "admin", "docker", "incus", "lxd", "root", "sudo", "wheel", "disk":
		return true
	default:
		return false
	}
}

// SeparationCheck verifies that agent and service identities differ.
func SeparationCheck(agent Identity, service Identity) Check {
	if agent.UID == service.UID {
		return Check{Status: CheckFail, Name: "service_user_separation", Message: "agent and broker service use the same uid"}
	}
	return Check{Status: CheckPass, Name: "service_user_separation", Message: "agent and broker service use different uids"}
}

// SecretFileChecks checks path stability and mode-bit access without reading
// file contents. Symlinks are inconclusive because this portable check cannot
// prove that their targets remain stable.
func SecretFileChecks(path string, agent Identity) []Check {
	pathCheck := secretPathStabilityCheck(path, agent)
	info, err := os.Stat(path) // #nosec G304 -- operator supplied doctor target.
	if err != nil {
		return []Check{pathCheck, {Status: CheckUnknown, Name: "secret_file", Message: "could not inspect secret file"}}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return []Check{pathCheck, {Status: CheckUnknown, Name: "secret_file", Message: "secret file ownership is unavailable"}}
	}
	checks := []Check{pathCheck, regularFileCheck(info), privateModeCheck(info)}
	ownerControlled := agent.UID == int(stat.Uid)
	checks = append(checks,
		accessCheck("secret_file_not_readable", "read", ownerControlled || canAccess(info.Mode().Perm(), int(stat.Uid), int(stat.Gid), agent, 0o400, 0o040, 0o004)),
		accessCheck("secret_file_not_writable", "write", ownerControlled || canAccess(info.Mode().Perm(), int(stat.Uid), int(stat.Gid), agent, 0o200, 0o020, 0o002)),
	)
	return checks
}

func secretPathStabilityCheck(path string, agent Identity) Check {
	absolute, parentInfo, failure := initializeSecretPath(path)
	if failure != nil {
		return *failure
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Clean(absolute), current), string(filepath.Separator)) {
		childPath := filepath.Join(current, component)
		childInfo, statErr := os.Lstat(childPath) // #nosec G304 -- operator supplied doctor target.
		if statErr != nil {
			return Check{Status: CheckUnknown, Name: "secret_path_stable", Message: "could not inspect every secret path component"}
		}
		if agentCanReplaceChild(parentInfo, childInfo, agent) {
			return Check{Status: CheckFail, Name: "secret_path_stable", Message: "agent can replace a secret path component by Unix ownership or mode bits"}
		}
		if childInfo.Mode()&os.ModeSymlink != 0 {
			return Check{Status: CheckUnknown, Name: "secret_path_stable", Message: "secret path contains a symbolic link"}
		}
		if aclCheck := secretPathACLCheck(childPath); aclCheck != nil {
			return *aclCheck
		}
		current = childPath
		parentInfo = childInfo
	}
	return Check{Status: CheckPass, Name: "secret_path_stable", Message: "secret path has no symlinks or agent-replaceable components by Unix ownership or mode bits"}
}

func secretPathACLCheck(path string) *Check {
	var message string
	switch pathACLState(path) {
	case aclPresent:
		message = "secret path contains an access control list"
	case aclUnknown:
		message = "secret path access control lists could not be inspected"
	case aclAbsent:
		return nil
	}
	return &Check{Status: CheckUnknown, Name: "secret_path_stable", Message: message}
}

func initializeSecretPath(path string) (string, os.FileInfo, *Check) {
	if validatex.HasParentTraversal(path) {
		failure := Check{Status: CheckUnknown, Name: "secret_path_stable", Message: "secret path contains parent traversal"}
		return "", nil, &failure
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		failure := Check{Status: CheckUnknown, Name: "secret_path_stable", Message: "could not resolve the secret path"}
		return "", nil, &failure
	}
	root, err := os.Lstat(string(filepath.Separator))
	if err != nil {
		failure := Check{Status: CheckUnknown, Name: "secret_path_stable", Message: "could not inspect the secret path"}
		return "", nil, &failure
	}
	if aclCheck := secretPathACLCheck(string(filepath.Separator)); aclCheck != nil {
		return "", nil, aclCheck
	}
	return absolute, root, nil
}

func agentCanReplaceChild(parent os.FileInfo, child os.FileInfo, agent Identity) bool {
	parentUID, parentGID, parentOK := unixOwnership(parent)
	if !parentOK {
		return true
	}
	childUID, _, childOK := unixOwnership(child)
	if !childOK {
		return true
	}
	if !parent.IsDir() {
		return true
	}
	if !agentCanModifyDirectory(parent, parentUID, parentGID, agent) {
		return false
	}
	if parent.Mode()&os.ModeSticky == 0 {
		return true
	}
	return ownsStickyEntry(agent.UID, parentUID, childUID)
}

func agentCanModifyDirectory(directory os.FileInfo, ownerUID int, ownerGID int, agent Identity) bool {
	if agent.UID == ownerUID {
		return true
	}
	mode := directory.Mode().Perm()
	canWrite := canAccess(mode, ownerUID, ownerGID, agent, 0o200, 0o020, 0o002)
	canSearch := canAccess(mode, ownerUID, ownerGID, agent, 0o100, 0o010, 0o001)
	return canWrite && canSearch
}

func unixOwnership(info os.FileInfo) (int, int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}

func ownsStickyEntry(agentUID int, parentUID int, childUID int) bool {
	return agentUID == 0 || agentUID == parentUID || agentUID == childUID
}

func regularFileCheck(info os.FileInfo) Check {
	if !info.Mode().IsRegular() {
		return Check{Status: CheckFail, Name: "secret_file_regular", Message: "secret path is not a regular file"}
	}
	return Check{Status: CheckPass, Name: "secret_file_regular", Message: "secret path is a regular file"}
}

func privateModeCheck(info os.FileInfo) Check {
	if info.Mode().Perm()&0o077 != 0 {
		return Check{Status: CheckFail, Name: "secret_file_private_mode", Message: "secret file grants group or other permissions"}
	}
	return Check{Status: CheckPass, Name: "secret_file_private_mode", Message: "secret file has private mode bits"}
}

func accessCheck(name string, operation string, allowed bool) Check {
	if allowed {
		return Check{Status: CheckFail, Name: name, Message: "agent can gain " + operation + " access to the secret file by Unix ownership or mode bits"}
	}
	return Check{Status: CheckPass, Name: name, Message: "agent cannot gain " + operation + " access to the secret file by Unix ownership or mode bits"}
}

func canAccess(mode os.FileMode, ownerUID int, ownerGID int, identity Identity, ownerBit os.FileMode, groupBit os.FileMode, otherBit os.FileMode) bool {
	if identity.UID == 0 {
		return true
	}
	if identity.UID == ownerUID {
		return mode&ownerBit != 0
	}
	if identity.GID == ownerGID || slices.Contains(identity.GroupIDs, ownerGID) {
		return mode&groupBit != 0
	}
	return mode&otherBit != 0
}

// NewReport computes the overall status from checks.
func NewReport(agent Identity, checks ...Check) Report {
	return Report{Status: OverallStatus(checks), Agent: agent, Checks: checks}
}

// OverallStatus computes the fail-closed verdict for a set of checks.
func OverallStatus(checks []Check) Status {
	status := StatusOK
	for _, check := range checks {
		switch check.Status {
		case CheckFail:
			return StatusUnsafe
		case CheckUnknown:
			status = StatusInconclusive
		case CheckWarn, CheckPass:
		default:
			status = StatusInconclusive
		}
	}
	return status
}

// WriteText writes a stable human-readable report.
func WriteText(w io.Writer, report Report) error {
	if _, err := fmt.Fprintln(w, strings.ToUpper(string(report.Status))); err != nil {
		return err
	}
	for _, check := range report.Checks {
		if _, err := fmt.Fprintf(w, "- %s %s: %s\n", check.Status, check.Name, check.Message); err != nil {
			return err
		}
	}
	return nil
}

// WriteJSON writes a secret-safe machine-readable report.
func WriteJSON(w io.Writer, report Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

// ExitCode maps a report status to the broker-family doctor exit contract.
func ExitCode(status Status) int {
	switch status {
	case StatusOK:
		return 0
	case StatusUnsafe:
		return 1
	case StatusInconclusive:
		return 2
	default:
		return 2
	}
}

// ValidateIdentity rejects incomplete synthetic identities used by consumers.
func ValidateIdentity(identity Identity) error {
	if strings.TrimSpace(identity.User) == "" || identity.UID < 0 || identity.GID < 0 {
		return errors.New("identity user, uid, and gid are required")
	}
	return nil
}
