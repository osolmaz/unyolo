//go:build linux || darwin

package hostcheck

import (
	"errors"
	"io/fs"
	"syscall"
)

func fileOwner(info fs.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("file owner is unavailable")
	}
	return stat.Uid, nil
}
