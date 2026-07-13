//go:build linux || darwin

package state

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

var ErrStateInUse = errors.New("broker state directory is already in use")

type lease struct{ file *os.File }

func acquireLease(path string) (*lease, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- path is rooted in the operator-selected state directory.
	if err != nil {
		return nil, fmt.Errorf("open state lease: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("secure state lease: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, ErrStateInUse
		}
		return nil, fmt.Errorf("acquire state lease: %w", err)
	}
	return &lease{file: file}, nil
}

func (l *lease) close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	return errors.Join(err, l.file.Close())
}
