//go:build !linux

package isolation

import (
	"context"
	"errors"
)

// Run reports that local isolation checks are only implemented on Linux.
func Run(context.Context, Options) (Report, error) {
	return Report{}, errors.New("hf-broker doctor isolation requires Linux")
}

// RunProbe is a no-op on unsupported platforms.
func RunProbe(string, int) ProbeResult {
	return ProbeResult{}
}

// DialUnix is unavailable through the isolation package on unsupported platforms.
func DialUnix(context.Context, string) bool {
	return false
}
