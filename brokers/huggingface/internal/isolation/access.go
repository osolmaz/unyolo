//go:build linux || darwin

package isolation

import unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"

func canRead(agent identity, stat fileStat) bool {
	return unyolodoctor.CanGainRead(doctorIdentity(agent), doctorFile(stat))
}

func canWrite(agent identity, stat fileStat) bool {
	return unyolodoctor.CanGainWrite(doctorIdentity(agent), doctorFile(stat))
}

func canReplaceDirectoryEntry(agent identity, stat fileStat) bool {
	return unyolodoctor.CanReplaceDirectoryEntry(doctorIdentity(agent), doctorFile(stat))
}

func canReplacePathEntry(agent identity, entry, parent fileStat) bool {
	return unyolodoctor.CanReplacePathEntry(doctorIdentity(agent), doctorFile(entry), doctorFile(parent))
}

func doctorIdentity(agent identity) unyolodoctor.Identity {
	groups := make([]int, 0, len(agent.gids))
	for group := range agent.gids {
		groups = append(groups, group)
	}
	return unyolodoctor.Identity{User: agent.user, UID: agent.uid, GID: agent.gid, GroupIDs: groups}
}

func doctorFile(stat fileStat) unyolodoctor.UnixFile {
	return unyolodoctor.UnixFile{Path: stat.path, Mode: stat.mode, UID: stat.uid, GID: stat.gid}
}

func lstat(path string) (fileStat, bool) { return statFile(path, false) }

func statTarget(path string) (fileStat, bool) {
	return localFileStat(unyolodoctor.InspectSymlinkTarget(path))
}

func statFile(path string, followSymlink bool) (fileStat, bool) {
	return localFileStat(unyolodoctor.InspectUnixFile(path, followSymlink))
}

func localFileStat(stat unyolodoctor.UnixFile, ok bool) (fileStat, bool) {
	if !ok {
		return fileStat{}, false
	}
	return fileStat{path: stat.Path, mode: stat.Mode, uid: stat.UID, gid: stat.GID}, true
}
