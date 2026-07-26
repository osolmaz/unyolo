package deployment

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func (engine *Engine) secretSourceOwner() (uint32, error) {
	if engine.options.Development || os.Geteuid() != 0 {
		uid := os.Geteuid()
		if uid < 0 {
			return 0, errors.New("resolve secret source owner")
		}
		return uint32(uid), nil // #nosec G115 -- UID is nonnegative and platform-bounded.
	}
	value := strings.TrimSpace(os.Getenv("SUDO_UID"))
	uid, err := strconv.ParseUint(value, 10, 32)
	if err != nil || uid == 0 {
		return 0, errors.New("production secret sources require a distinct sudo invoking user")
	}
	return uint32(uid), nil
}

func openSecretSourceNoFollow(path string, owner uint32) (*os.File, error) {
	root, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("open secret source root")
	}
	fd := root
	parts := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts[:len(parts)-1] {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return nil, errors.New("open secret source parent")
		}
		fd = next
	}
	fileFD, openErr := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	_ = unix.Close(fd)
	if openErr != nil {
		return nil, errors.New("open secret source")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fileFD, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 || stat.Uid != owner {
		_ = unix.Close(fileFD)
		return nil, errors.New("secret source must be an invoking-user-owned owner-only regular file")
	}
	file := os.NewFile(uintptr(fileFD), path)
	if file == nil {
		_ = unix.Close(fileFD)
		return nil, errors.New("open secret source")
	}
	return file, nil
}
