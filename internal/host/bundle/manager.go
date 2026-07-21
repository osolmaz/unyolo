package bundle

import (
	"context"
)

type commandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return runCommand(ctx, name, args...)
}

// NewNativeManager returns the supported native system service adapter.
func NewNativeManager() ServiceManager { return newNativeManager(execRunner{}) }
