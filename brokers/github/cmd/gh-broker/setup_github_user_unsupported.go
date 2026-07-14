//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package main

import "errors"

func preserveGitHubUserStateOwnership(_ string) error {
	return errors.New("GitHub user credential setup is unsupported on this platform")
}
