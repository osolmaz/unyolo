//go:build darwin

package doctor

import (
	"context"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

type darwinACLEntry struct {
	principal string
	action    string
	perms     []string
}

var darwinEntryACLPerms = map[string]bool{
	"append": true, "chown": true, "delete": true, "full_control": true,
	"read": true, "readattr": true, "readextattr": true, "readsecurity": true,
	"write": true, "writeattr": true, "writeextattr": true, "writeowner": true, "writesecurity": true,
}

var darwinSocketEntryACLPerms = map[string]bool{
	"append": true, "chown": true, "delete": true, "full_control": true,
	"write": true, "writeattr": true, "writeextattr": true, "writeowner": true, "writesecurity": true,
}

var darwinParentACLPerms = map[string]bool{
	"add_file": true, "add_subdirectory": true, "append": true, "chown": true,
	"delete": true, "delete_child": true, "full_control": true, "write": true,
	"writeattr": true, "writeextattr": true, "writeowner": true, "writesecurity": true,
}

var darwinACLFixedPrincipals = map[string]string{
	"everyone": "everyone", "everyone@": "everyone", "group@": "filegroup", "owner@": "owner",
}

// DarwinACLGrantState checks whether a macOS ACL grants identity dangerous
// access for candidate's file, socket, or parent-directory role.
func DarwinACLGrantState(identity Identity, candidate ACLPath) ACLState {
	file, ok := InspectUnixFile(candidate.Path, false)
	if !ok {
		return ACLUnknown
	}
	entries, state := darwinACLEntries(candidate.Path)
	if state != ACLAbsent {
		return state
	}
	return darwinACLEntriesState(identity, file, entries, candidate.Kind)
}

func darwinACLEntriesState(identity Identity, file UnixFile, entries []darwinACLEntry, kind ACLPathKind) ACLState {
	for _, entry := range entries {
		if entry.action == "deny" || !darwinACLEntryHasDangerousGrant(entry, kind) {
			continue
		}
		matches, ok := darwinACLAppliesToIdentity(entry.principal, identity, file)
		if !ok {
			return ACLUnknown
		}
		if matches && entry.action == "allow" {
			return ACLPresent
		}
	}
	return ACLAbsent
}

func darwinACLEntries(path string) ([]darwinACLEntry, ACLState) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/ls", "-lde", path)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	output, err := command.Output()
	if ctx.Err() != nil || err != nil {
		return nil, ACLUnknown
	}
	return parseDarwinACLEntries(string(output))
}

func parseDarwinACLEntries(output string) ([]darwinACLEntry, ACLState) {
	lines := strings.Split(output, "\n")
	var entries []darwinACLEntry
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue
		}
		entry, ok := parseDarwinACLEntry(line)
		if !ok {
			return nil, ACLUnknown
		}
		entries = append(entries, entry)
	}
	return entries, ACLAbsent
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
	perms := splitDarwinACLPerms(fields[actionIndex+1:])
	if len(perms) == 0 {
		return darwinACLEntry{}, false
	}
	return darwinACLEntry{principal: strings.Join(fields[:actionIndex], " "), action: fields[actionIndex], perms: perms}, true
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
	parts := strings.Split(strings.Join(fields, ","), ",")
	perms := make([]string, 0, len(parts))
	for _, part := range parts {
		perm := normalizeDarwinACLPerm(part)
		if perm != "" {
			perms = append(perms, perm)
		}
	}
	return perms
}

func normalizeDarwinACLPerm(perm string) string {
	perm = strings.TrimSpace(strings.ToLower(perm))
	perm = strings.ReplaceAll(perm, "-", "_")
	return strings.ReplaceAll(perm, "_security", "security")
}

func darwinACLAppliesToIdentity(principal string, identity Identity, file UnixFile) (bool, bool) {
	kind, value, ok := darwinACLPrincipal(principal)
	if !ok {
		return false, false
	}
	switch kind {
	case "everyone":
		return true, true
	case "filegroup":
		return identity.GID == file.GID || slices.Contains(identity.GroupIDs, file.GID), true
	case "group":
		return darwinACLGroupApplies(value, identity), true
	case "owner":
		return identity.UID == file.UID, true
	case "user":
		return darwinACLUserApplies(value, identity), true
	default:
		return false, false
	}
}

func darwinACLPrincipal(principal string) (string, string, bool) {
	principal = strings.TrimSpace(principal)
	if kind, ok := darwinACLFixedPrincipals[principal]; ok {
		return kind, "", true
	}
	kind, value, ok := strings.Cut(principal, ":")
	return kind, value, ok && (kind == "user" || kind == "group")
}

func darwinACLUserApplies(value string, identity Identity) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if uid, err := strconv.Atoi(value); err == nil {
		return uid == identity.UID
	}
	return value == identity.User
}

func darwinACLGroupApplies(value string, identity Identity) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if value == "everyone" || value == "everyone@" {
		return true
	}
	if gid, err := strconv.Atoi(value); err == nil {
		return gid == identity.GID || slices.Contains(identity.GroupIDs, gid)
	}
	return slices.Contains(identity.GroupNames, value)
}

func darwinACLEntryHasDangerousGrant(entry darwinACLEntry, kind ACLPathKind) bool {
	dangerous := darwinEntryACLPerms
	switch kind {
	case ACLParentDirectory:
		dangerous = darwinParentACLPerms
	case ACLSocketEntry:
		dangerous = darwinSocketEntryACLPerms
	}
	for _, perm := range entry.perms {
		if dangerous[perm] {
			return true
		}
	}
	return false
}

func pathACLState(path string) aclState {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/ls", "-lde", path)
	command.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	output, err := command.Output()
	if ctx.Err() != nil || err != nil {
		return aclUnknown
	}
	lines := strings.Split(string(output), "\n")
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) != "" {
			return aclPresent
		}
	}
	return aclAbsent
}
