// Package fsx provides small durability helpers for trusted filesystem paths.
package fsx

import (
	"errors"
	"os"
)

// SyncDirectory flushes directory metadata after an atomic filesystem change.
func SyncDirectory(path string) error {
	directory, err := os.Open(path) // #nosec G304 -- callers supply trusted, validated directories.
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}
