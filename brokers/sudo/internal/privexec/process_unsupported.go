//go:build !linux && !darwin

package privexec

import "errors"

func killProcessGroup(int) error { return errors.New("process groups are unsupported") }
