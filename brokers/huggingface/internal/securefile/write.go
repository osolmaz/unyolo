// Package securefile owns durable writes shared by broker-private stores.
package securefile

import (
	"errors"
	"os"
)

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
