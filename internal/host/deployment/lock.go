package deployment

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type hostLock struct{ file *os.File }

func acquireHostLock(stateDirectory string) (*hostLock, error) {
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(stateDirectory, "deployment.lock"), os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- fixed private host state path.
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, err
	}
	return &hostLock{file: file}, nil
}

func (lock *hostLock) close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(lock.file.Fd()), unix.LOCK_UN), lock.file.Close())
}
