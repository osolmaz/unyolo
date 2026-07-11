//go:build !linux && !darwin

package hostcheck

import (
	"errors"
	"io/fs"
)

func fileOwner(fs.FileInfo) (uint32, error) {
	return 0, errors.New("file ownership checks are unsupported")
}
