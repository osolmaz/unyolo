//go:build linux || darwin

package privexec

import "syscall"

func killProcessGroup(pid int) error { return syscall.Kill(-pid, syscall.SIGKILL) }
