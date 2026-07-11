//go:build darwin

package hostcheck

func KernelExecutionSafety() (bool, error) { return false, nil }
