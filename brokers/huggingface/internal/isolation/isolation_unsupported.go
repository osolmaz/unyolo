//go:build !linux && !darwin

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
func RunProbe(string, int, string) ProbeResult {
	return ProbeResult{}
}
