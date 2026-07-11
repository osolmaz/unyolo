//go:build darwin

package hostcheck

// Darwin ACL inspection is reported as a platform limitation by doctor.
func validatePathACL(string, bool) error { return nil }
