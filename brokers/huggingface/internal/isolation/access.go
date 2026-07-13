//go:build linux || darwin

package isolation

import bkdoctor "github.com/osolmaz/brokerkit/doctor"

func canRead(agent identity, stat fileStat) bool {
	return bkdoctor.CanGainRead(doctorIdentity(agent), doctorFile(stat))
}

func canWrite(agent identity, stat fileStat) bool {
	return bkdoctor.CanGainWrite(doctorIdentity(agent), doctorFile(stat))
}

func canReplaceDirectoryEntry(agent identity, stat fileStat) bool {
	return bkdoctor.CanReplaceDirectoryEntry(doctorIdentity(agent), doctorFile(stat))
}

func canReplacePathEntry(agent identity, entry, parent fileStat) bool {
	return bkdoctor.CanReplacePathEntry(doctorIdentity(agent), doctorFile(entry), doctorFile(parent))
}

func doctorIdentity(agent identity) bkdoctor.Identity {
	groups := make([]int, 0, len(agent.gids))
	for group := range agent.gids {
		groups = append(groups, group)
	}
	return bkdoctor.Identity{User: agent.user, UID: agent.uid, GID: agent.gid, GroupIDs: groups}
}

func doctorFile(stat fileStat) bkdoctor.UnixFile {
	return bkdoctor.UnixFile{Path: stat.path, Mode: stat.mode, UID: stat.uid, GID: stat.gid}
}

func lstat(path string) (fileStat, bool) { return statFile(path, false) }

func statTarget(path string) (fileStat, bool) {
	return localFileStat(bkdoctor.InspectSymlinkTarget(path))
}

func statFile(path string, followSymlink bool) (fileStat, bool) {
	return localFileStat(bkdoctor.InspectUnixFile(path, followSymlink))
}

func localFileStat(stat bkdoctor.UnixFile, ok bool) (fileStat, bool) {
	if !ok {
		return fileStat{}, false
	}
	return fileStat{path: stat.Path, mode: stat.Mode, uid: stat.UID, gid: stat.GID}, true
}
