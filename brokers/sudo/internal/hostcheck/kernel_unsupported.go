//go:build !linux && !darwin

package hostcheck

import "errors"

func KernelExecutionSafety() (bool, error) { return false, errors.New("platform is unsupported") }
