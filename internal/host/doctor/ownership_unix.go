//go:build linux || darwin

package doctor

import (
	"os"
	"syscall"
)

func unixOwnership(info os.FileInfo) (int, int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
