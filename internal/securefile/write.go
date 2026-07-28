// Package securefile owns durable writes shared by unYOLO-private stores.
package securefile

import (
	"errors"
	"os"
	"path/filepath"
)

// AtomicWrite commits one private file through a same-directory temporary.
func AtomicWrite(path string, data []byte, mode os.FileMode, noun string) error {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+"-*")
	if err != nil {
		return errors.New("create " + noun)
	}
	temporary := file.Name()
	defer func() { _ = os.Remove(temporary) }()
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		return errors.New("secure " + noun)
	}
	if err := WriteAndSync(file, data, noun); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("replace " + noun)
	}
	return nil
}

// WriteAndSync writes, syncs, and closes file, failing at the first incomplete
// durability step.
func WriteAndSync(file *os.File, data []byte, noun string) error {
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return errors.New("write " + noun)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return errors.New("sync " + noun)
	}
	if err := file.Close(); err != nil {
		return errors.New("close " + noun)
	}
	return nil
}
