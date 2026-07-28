//go:build linux || darwin

package isolation

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	unyolodoctor "github.com/osolmaz/unyolo/internal/host/doctor"
)

func runParentWriteChecks(report *Report, agent identity, dir, name string) {
	for _, candidate := range unyolodoctor.ParentDirs(dir) {
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
	entry, entryOK := lstat(unyolodoctor.CleanPath(path))
	if !entryOK {
		add(report, CheckUnknown, name, pathEntryInspectMessage(name))
		return
	}
	parent, parentOK := lstat(unyolodoctor.ResolvedDir(path))
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
	resolved, ok := unyolodoctor.ResolvedCleanPath(path)
	if !ok {
		add(report, CheckUnknown, prefix+"_path", pathMessagesFor(prefix).resolveUnknown)
		return
	}
	if resolved == unyolodoctor.CleanPath(path) {
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

func parentPassMessage(name string) string { return pathMessagesFor(name).parentPass }

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
	stat, ok := lstat(unyolodoctor.CleanPath(path))
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
