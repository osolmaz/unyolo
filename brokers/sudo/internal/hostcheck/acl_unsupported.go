//go:build !linux && !darwin

package hostcheck

import "errors"

func validatePathACL(string, bool) error { return errors.New("ACL inspection is unsupported") }
