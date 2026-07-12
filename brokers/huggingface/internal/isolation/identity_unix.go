//go:build linux || darwin

package isolation

import (
	"fmt"
	"os/user"
	"sort"
	"strconv"
)

func lookupUserIdentity(name string, pid int) (identity, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return identity{}, fmt.Errorf("lookup agent user %q: %w", name, err)
	}
	return userIdentity(account, pid)
}

func userIdentity(account *user.User, pid int) (identity, error) {
	uid, gid, err := parseUserIDs(account)
	if err != nil {
		return identity{}, err
	}
	gids, groups, err := userGroupMaps(account, gid)
	if err != nil {
		return identity{}, err
	}
	return identity{user: account.Username, uid: uid, gid: gid, gidSet: true, gids: gids, groups: groups, pid: pid}, nil
}

func parseUserIDs(account *user.User) (int, int, error) {
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for %q: %w", account.Username, err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for %q: %w", account.Username, err)
	}
	return uid, gid, nil
}

func userGroupMaps(account *user.User, primaryGID int) (map[int]bool, map[string]bool, error) {
	values, err := account.GroupIds()
	if err != nil {
		return nil, nil, fmt.Errorf("lookup groups for %q: %w", account.Username, err)
	}
	gids := make(map[int]bool, len(values))
	groups := map[string]bool{}
	for _, raw := range values {
		gid, parseErr := strconv.Atoi(raw)
		if parseErr != nil {
			continue
		}
		gids[gid] = true
		if group, lookupErr := user.LookupGroupId(raw); lookupErr == nil {
			groups[group.Name] = true
		}
	}
	gids[primaryGID] = true
	if group, lookupErr := user.LookupGroupId(account.Gid); lookupErr == nil {
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
