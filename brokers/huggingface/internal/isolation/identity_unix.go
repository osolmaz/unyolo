//go:build linux || darwin

package isolation

import (
	"fmt"
	"os/user"
	"sort"
	"strconv"

	unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"
)

func lookupUserIdentity(name string, pid int) (identity, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return identity{}, fmt.Errorf("lookup agent user %q: %w", name, err)
	}
	return userIdentity(account, pid)
}

func userIdentity(account *user.User, pid int) (identity, error) {
	resolved, err := unyolodoctor.IdentityFromUser(account)
	if err != nil {
		return identity{}, err
	}
	groups := make(map[string]bool, len(resolved.GroupNames))
	for _, group := range resolved.GroupNames {
		groups[group] = true
	}
	return identity{
		user: account.Username, uid: resolved.UID, gid: resolved.GID, gidSet: true,
		gids: gidsMap(resolved.GroupIDs), groups: groups, pid: pid,
	}, nil
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
