//go:build !linux && !darwin

package doctor

func pathACLState(string) aclState {
	return aclUnknown
}
