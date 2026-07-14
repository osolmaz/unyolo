//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import "testing"

func assertSetupStateOwnership(_ *testing.T, _ string, _ ...string) {}
