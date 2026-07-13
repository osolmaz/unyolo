//go:build !linux && !darwin

package doctor

import "os"

func unixOwnership(os.FileInfo) (int, int, bool) {
	return 0, 0, false
}
