//go:build linux || darwin

package isolation

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	bkdoctor "github.com/osolmaz/brokerkit/internal/host/doctor"
)

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
