package component

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func readBoundedNoFollow(path string, maximum int64) ([]byte, error) {
	parent, err := openDirectoryNoFollow(filepath.Dir(path), false, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, filepath.Base(path), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open component file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maximum {
		clear(data)
		return nil, errors.Join(readErr, closeErr, errors.New("component file exceeds size limit"))
	}
	return data, nil
}
